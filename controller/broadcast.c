/*
 * Author: Jacob T. Grycel
 * Description: Broadcast protocol implementation:
 *
 *              SCEWL Controller Universal Messaging (SCUM)
 *
 *              Based on the Secure Real-time Transport Protocol (SRTP)
 *
 *
 *            ░██████╗░█████╗░██╗░░░██╗███╗░░░███╗
 *            ██╔════╝██╔══██╗██║░░░██║████╗░████║
 *            ╚█████╗░██║░░╚═╝██║░░░██║██╔████╔██║
 *            ░╚═══██╗██║░░██╗██║░░░██║██║╚██╔╝██║
 *            ██████╔╝╚█████╔╝╚██████╔╝██║░╚═╝░██║
 *            ╚═════╝░░╚════╝░░╚═════╝░╚═╝░░░░░╚═╝
 */

#include "broadcast.h"
#include "controller.h"
#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"

#include <string.h>



////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                           Internal Functions                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////



/*
 *
 * Utility
 *
 */


// Check incoming data for valid and legal header - data cannot be trusted
static int scum_check_frame(char *data_buf, size_t data_len)
{
  struct scum_hdr *hdr;

  // Get header
  hdr = (struct scum_hdr *)data_buf;

  // Check frame and data size is valid
  if (data_len < SCUM_HDR_LEN) {
    mbedtls_printf("Incoming SCEWL data too short for full SCUM header");
    return -1;
  } else if (data_len > SCUM_MTU) {
    mbedtls_printf("Incoming SCEWL data longer than SCUM MTU");
    return -2;
  } else if (SCUM_HDR_LEN + hdr->length + SCUM_TAG_LEN != data_len) {
    mbedtls_printf("Incoming SCUM and SCEWL lengths are not compatible");
    return -3;
  }

  return 0;
}


/*
 *
 * Key Management
 *
 */


// Derive new key from master data session key
static int scum_derive_keys(struct scum_crypto *crypto)
{
  int ret;

  // Create IV buffer
  uint8_t iv_buf[CIPHER_BLOCK_LEN];
  uint8_t key_buf[S_KEY_LEN];
  
  // Copy salt into IV buf
  // Bytes 0,1 are 0x00
  memset(iv_buf, 0, CIPHER_BLOCK_LEN);
  memcpy(iv_buf+2, crypto->m_salt, 12);

  // Add in extra data
  iv_buf[9]  ^= 0x00; // Key type ID
  iv_buf[10] ^= ((crypto->key_count >> 24) & 0xFF); // XOR key derivation counter
  iv_buf[11] ^= ((crypto->key_count >> 16) & 0xFF);
  iv_buf[12] ^= ((crypto->key_count >> 8) & 0xFF);
  iv_buf[13] ^= (crypto->key_count & 0xFF);

  // Derive key block 0
  ret = mbedtls_aes_crypt_ecb(&crypto->aes, MBEDTLS_AES_ENCRYPT, iv_buf, key_buf);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_crypt_ecb returned -%#06x", (unsigned int) -ret);
    return -1;
  }
  // Derive key block 1
  iv_buf[15] ^= 0x01;
  ret = mbedtls_aes_crypt_ecb(&crypto->aes, MBEDTLS_AES_ENCRYPT, iv_buf, key_buf+CIPHER_BLOCK_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_crypt_ecb returned -%#06x", (unsigned int) -ret);
    return -2;
  }

  // Derive salt
  iv_buf[15] ^= 0x01; // Clear key block counter
  iv_buf[9] ^= 0x02; // Salt type ID
  ret = mbedtls_aes_crypt_ecb(&crypto->aes, MBEDTLS_AES_ENCRYPT, iv_buf, crypto->e_salt);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_crypt_ecb returned -%#06x", (unsigned int) -ret);
    return -3;
  }
  memset(crypto->e_salt+S_SALT_LEN, 0, CIPHER_BLOCK_LEN-S_SALT_LEN); // Only 12 bytes

  // Update session key
  ret = mbedtls_gcm_setkey(&crypto->gcm, MBEDTLS_CIPHER_ID_AES, key_buf, S_KEY_LEN*8);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_gcm_setkey returned -%#06x", (unsigned int) -ret);
    return -4;
  }

  crypto->key_count++;

  return 0;
}

// Check key status and refresh -- helper function avoids always buffers
static int scum_update_keys(struct scum_crypto *crypto, uint64_t msg_count)
{
  int ret;

  // Only re-key at the key derivation rate
  if ((crypto->kdr == 0) || (msg_count % crypto->kdr != 0)) {
    return 0;
  }
  
  ret = scum_derive_keys(crypto);
  if (ret != 0) {
    mbedtls_printf("Key refresh failed");
    return -1;
  }

  return 0;
}


/*
 *
 * SCUM Setup
 *
 */


// Setup SCUM crypto context
static int scum_crypto_setup(struct scum_crypto *crypto, char *key, char *salt, uint32_t kdr)
{
  int ret;

  // Initialize variables
  crypto->key_count = 0;
  crypto->kdr = kdr;

  // Initialize contexts
  mbedtls_gcm_init(&crypto->gcm);
  mbedtls_aes_init(&crypto->aes);

  // Load PRF key
  ret = mbedtls_aes_setkey_enc(&crypto->aes, (uint8_t *)key, S_KEY_LEN*8);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_setkey_enc returned -%#06x", (unsigned int) -ret);
    return -1;
  }

  // Load PRF salt
  memcpy(crypto->m_salt, salt, S_SALT_LEN);

  // Derive session key
  ret = scum_derive_keys(crypto);
  if (ret != 0) {
    mbedtls_printf("Key initialization failed");
    return -2;
  }

  return 0;
}

// Setup SCUM data session
static int scum_data_setup(struct scum_data_session *session, char *key, char *salt, char *app_buf, char *rad_buf)
{
  int ret;

  // Initialize session parameters
  session->status = S_UNSYNC;
  session->msg_count = 0;
  session->in_received = 0;
  session->out_remaining = 0;
  session->out_msg_len = 0;
  session->recv_src_id = 0;
  session->app_buf = app_buf;
  session->rad_buf = rad_buf;

  // Set up crypto context
  ret = scum_crypto_setup(&session->crypto, key, salt, SCUM_DEFAULT_KDR);
  if (ret != 0) {
    mbedtls_printf("Data session key setup failed");
    return -1;
  }

  return 0;
}

// Setup SCUM sync session
static int scum_sync_setup(struct scum_sync_session *session, char *key, char *salt, char *rad_buf)
{
  int ret;

  // Initialize session parameters
  session->status = S_IDLE;
  session->rad_buf = rad_buf;

  // Initialize cryptographic primitives
  rng_module_setup(&session->rng, NULL, 0);

  // Set up crypto context
  ret = scum_crypto_setup(&session->crypto, key, salt, 0);
  if (ret != 0) {
    mbedtls_printf("Sync session key setup failed");
    return -1;
  }

  return 0;
}


/*
 *
 * Data Encryption / Decryption Core
 *
 */


// Create data frame GCM IV
static void scum_create_iv(struct scum_crypto *crypto, uint8_t *iv, struct scum_hdr *hdr)
{
  // Extract and place header
  iv[0] = hdr->end_marker;
  iv[1] = hdr->type;
  iv[2] = (hdr->length >> 8) & 0xFF;
  iv[3] = hdr->length & 0xFF;
  iv[4] = (hdr->seq_number >> 56) & 0xFF;
  iv[5] = (hdr->seq_number >> 48) & 0xFF;
  iv[6] = (hdr->seq_number >> 40) & 0xFF;
  iv[7] = (hdr->seq_number >> 32) & 0xFF;
  iv[8] = (hdr->seq_number >> 24) & 0xFF;
  iv[9] = (hdr->seq_number >> 16) & 0xFF;
  iv[10] = (hdr->seq_number >> 8) & 0xFF;
  iv[11] = hdr->seq_number & 0xFF;
  
  for (int i = 0; i < SCUM_IV_LEN; i++) {
    iv[i] ^= crypto->e_salt[i];
  }
}

// Packet encryption and transmission core
// Beginning of `output_buf` should hold a SCUM header already
// Return number of bytes sent
static int scum_push_frame(struct scum_crypto *crypto, char *data_buf, char *output_buf)
{
  struct scum_hdr *hdr;
  uint8_t iv[SCUM_IV_LEN];
  uint8_t *ptext_ptr;
  uint8_t *ctext_ptr;
  uint8_t *tag_ptr;
  int ret;

  // Set up encryption data
  hdr = (struct scum_hdr *)output_buf;
  ptext_ptr = (uint8_t *)data_buf;
  ctext_ptr = (uint8_t *)output_buf+SCUM_HDR_LEN;
  tag_ptr = (uint8_t *)output_buf+SCUM_HDR_LEN+hdr->length;
  scum_create_iv(crypto, iv, hdr);

  // Encrypt data
  ret = mbedtls_gcm_crypt_and_tag(&crypto->gcm, MBEDTLS_GCM_ENCRYPT,
                            hdr->length,
                            iv, SCUM_IV_LEN,
                            (uint8_t *)hdr, SCUM_HDR_LEN,
                            ptext_ptr,
                            ctext_ptr,
                            SCUM_TAG_LEN, tag_ptr);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_gcm_crypt_and_tag returned -%#06x", (unsigned int) -ret);
    return -1;
  }

  // Send encrypted packet
  handle_brdcst_send(output_buf, SCUM_HDR_LEN+hdr->length+SCUM_TAG_LEN);

  return hdr->length;
}

// Packet decryption and storing core
// `input_buf` will hold the decrypted data
// Return number of bytes received
static int scum_absorb_frame(struct scum_crypto *crypto, char *data_buf, char *input_buf)
{
  struct scum_hdr *hdr;
  uint8_t iv[SCUM_IV_LEN];
  uint8_t *ctext_ptr;
  uint8_t *tag_ptr;
  uint8_t *ptext_ptr;
  int ret;

  // Set up decryption data
  hdr = (struct scum_hdr *)data_buf;
  ctext_ptr = (uint8_t *)data_buf+SCUM_HDR_LEN;
  tag_ptr = (uint8_t *)data_buf+SCUM_HDR_LEN+hdr->length;
  ptext_ptr = (uint8_t *)input_buf;
  scum_create_iv(crypto, iv, hdr);

  // Decrypt data
  ret = mbedtls_gcm_auth_decrypt(&crypto->gcm,
                           hdr->length,
                           iv, SCUM_IV_LEN,
                           (uint8_t *)hdr, SCUM_HDR_LEN,
                           tag_ptr, SCUM_TAG_LEN,
                           ctext_ptr,
                           ptext_ptr);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_gcm_auth_decrypt returned -%#06x", (unsigned int) -ret);
    return -1;
  }

  return hdr->length;
}


/*
 *
 * Data Session Operations
 *
 */


// Send next data frame from app buffer to radio buffer
static int scum_data_push(struct scum_data_session *session)
{
  struct scum_hdr *hdr;
  char *read_ptr;
  char *write_ptr;
  int ret;

  // Construct header in output buffer
  hdr = (struct scum_hdr *)session->rad_buf;
  hdr->type = S_DATA;
  hdr->seq_number = session->msg_count;

  if (session->out_remaining <= SCUM_MAX_DATA_LEN) {
    hdr->length = session->out_remaining;
    hdr->end_marker = 1;
  } else {
    hdr->length = SCUM_MAX_DATA_LEN;
    hdr->end_marker = 0;
  }

  // Set up pointers
  read_ptr = session->app_buf+(session->out_msg_len-session->out_remaining);
  write_ptr = session->rad_buf;

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to send SCUM frame");
    return -1;
  }

  // Update stream status
  session->out_remaining -= ret;

  // Update session status
  session->msg_count++;

  // Refresh keys if needed
  ret = scum_update_keys(&session->crypto, session->msg_count);
  if (ret != 0) {
    mbedtls_printf("Data session (send) key refresh failed");
    return -2;
  }

  // Return stream status
  return hdr->end_marker;
}

// Process outgoing broadcast message
static int scum_data_send(struct scum_data_session *session, size_t data_len)
{ 
  int ret;

  // Start new data stream if not being used (unsynced state will bypass)
  if (session->status == S_IDLE) {
    session->out_remaining = data_len;
    session->out_msg_len = data_len;
    session->status = S_SEND;
  }
  if (session->status == S_SEND) {
    do {
      ret = scum_data_push(session);
      if (ret < 0) {
        mbedtls_printf("Failed to push SCUM data frame");
        session->status = S_IDLE;
        return -1;
      }
    } while (ret != 1);
    session->status = S_DONE;
  }
  if (session->status == S_DONE) {
    mbedtls_printf("Sent broadcast: %.*s", session->out_msg_len, session->app_buf);
    session->status = S_IDLE;
  }

  return 0;
}

// Receive next data frame from radio buffer into app buffer
static int scum_data_absorb(struct scum_data_session *session)
{
  struct scum_hdr *hdr;
  char *read_ptr;
  char *write_ptr;
  int ret;

  // Get header
  hdr = (struct scum_hdr *)session->rad_buf;

  // Make sure message can fit and is in sequence
  if (hdr->length + session->in_received > MAX_SCEWL_LEN) {
    mbedtls_printf("Attempted to receive more than MAX_SCEWL_LEN bytes");
    return -1;
  } else if (hdr->seq_number < session->msg_count) {
    mbedtls_printf("Attempted to receive message with earlier sequence number");
    return -2;
  }

  // Set up pointers
  read_ptr = session->rad_buf;
  write_ptr = session->app_buf + session->in_received;

  // Decrypt and absorb
  ret = scum_absorb_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return -3;
  }

  // Update stream status
  session->in_received += ret;

  // Update session status
  session->msg_count++;

  // Refresh keys if needed
  ret = scum_update_keys(&session->crypto, session->msg_count);
  if (ret != 0) {
    mbedtls_printf("Data session (receive) key refresh failed");
    return -4;
  }

  // Return stream status
  return hdr->end_marker;
}

// Process incoming broadcast message
static int scum_data_receive(struct scum_data_session *session, scewl_id_t src_id)
{
  int ret;

  // Start new data stream or continue current one (unsynced state will bypass)
  if (session->status == S_IDLE) {
    session->recv_src_id = src_id;
    session->in_received = 0;
    session->status = S_RECV;
  }
  if (session->status == S_RECV) {
    // Check the same SED is broadcasting
    if (src_id != session->recv_src_id) {
      mbedtls_printf("Ignoring broadcast from ID %d during broadcast from ID %d", src_id, session->recv_src_id);
      return 0;
    }

    // Handle the frame - check for error or end marker
    ret = scum_data_absorb(session);
    if (ret < 0) {
      mbedtls_printf("Failed to absorb SCUM data frame");
      session->status = S_IDLE;
      return -1;
    } else if (ret == 1) {
      session->status = S_DONE;
    }
  }
  if (session->status == S_DONE) {
    // Send to CPU
    handle_brdcst_recv((char *)session->app_buf, session->recv_src_id, session->in_received);
    mbedtls_printf("Received broadcast from %d: %.*s", session->recv_src_id, session->in_received, session->app_buf);
    session->status = S_IDLE;
  }

  return 0;
}


/*
 *
 * Sync Session Operations
 *
 */

// Process outgoing sync request
static int scum_sync_req_send(struct scum_sync_session *session)
{
  struct scum_hdr *hdr;
  char *read_ptr;
  char *write_ptr;
  int ret;

  // Check if sync session is running
  if (session->status != S_IDLE) {
    mbedtls_printf("Tried sending a sync request while receiving another");
    return -1;
  }

  // Construct header in output buffer
  hdr = (struct scum_hdr *)session->rad_buf;
  hdr->type = S_SYNC_REQ;
  hdr->seq_number = 0;
  hdr->length = SCUM_SYNC_REQ_LEN;
  hdr->end_marker = 1;

  // Create random message
  ret = mbedtls_hmac_drbg_random(&session->rng, session->sync_bytes, SCUM_SYNC_REQ_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_hmac_drbg_random returned -%#06x", (unsigned int) -ret);
    return -2 ;
  }

  // Set up pointers
  read_ptr = (char *)session->sync_bytes;
  write_ptr = session->rad_buf;

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to send sync request frame");
    return -3;
  }

  // Update session status
  session->status = S_SYNC;

  return 0;
}

// Process incoming sync request
static int scum_sync_req_handle(struct scum_sync_session *session, struct scum_data_session *data_session)
{
  struct scum_hdr *hdr;
  uint8_t msg_buf[SCUM_SYNC_RESP_LEN];
  uint32_t prev_key_count;
  char *read_ptr;
  char *write_ptr;
  int ret;

  // Get header
  hdr = (struct scum_hdr *)session->rad_buf;

  // Check if sync session is running
  if (session->status != S_IDLE) {
    mbedtls_printf("Ignorning sync request message");
    return 0;
  }

  // Check message length
  if (hdr->length != SCUM_SYNC_REQ_LEN) {
    mbedtls_printf("Got a sync request with invalid message length");
    return -1;
  }

  // Set up pointers
  read_ptr = session->rad_buf;
  write_ptr = (char *)msg_buf;

  // Decrypt
  ret = scum_absorb_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return -2;
  }

  // Copy message count and previous key
  prev_key_count = data_session->crypto.key_count-1;
  memcpy(msg_buf+SCUM_SYNC_REQ_LEN, (uint8_t *)&data_session->msg_count, SCUM_MSG_COUNT_LEN);
  memcpy(msg_buf+SCUM_SYNC_REQ_LEN+SCUM_MSG_COUNT_LEN, (uint8_t *)&prev_key_count, SCUM_KEY_COUNT_LEN);

  // Construct outgoing header
  hdr = (struct scum_hdr *)session->rad_buf;
  hdr->type = S_SYNC_RESP;
  hdr->seq_number = 0;
  hdr->length = SCUM_SYNC_RESP_LEN;
  hdr->end_marker = 1;

  // Set up pointers
  read_ptr = (char *)msg_buf;
  write_ptr = session->rad_buf;

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to send SCUM frame");
    return -3;
  }

  return 0;
}

// Process incoming sync response
static int scum_sync_resp_receive(struct scum_sync_session *session, struct scum_data_session *data_session)
{
  struct scum_hdr *hdr;
  uint8_t msg_buf[SCUM_SYNC_RESP_LEN];
  char *read_ptr;
  char *write_ptr;
  int ret;

  // Check if sync session is running
  if (session->status != S_SYNC) {
    mbedtls_printf("Ignoring sync response message");
    return 0;
  }

  // Get header
  hdr = (struct scum_hdr *)session->rad_buf;

  // Check message length
  if (hdr->length != SCUM_SYNC_RESP_LEN) {
    mbedtls_printf("Got a synq response with invalid message length");
    return -1;
  }

  // Set up pointers
  read_ptr = session->rad_buf;
  write_ptr = (char *)msg_buf;

  // Decrypt
  ret = scum_absorb_frame(&session->crypto, read_ptr, write_ptr);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return -2;
  }

  // Check random bytes match
  ret = memcmp(msg_buf, session->sync_bytes, SCUM_SYNC_REQ_LEN);
  if (ret != 0) {
    mbedtls_printf("Received incorrect sync bytes in synq response");
    return -3;
  }

  // Copy message and key counts
  memcpy((uint8_t *)&data_session->msg_count, msg_buf+SCUM_SYNC_REQ_LEN, SCUM_MSG_COUNT_LEN);
  memcpy((uint8_t *)&data_session->crypto.key_count, msg_buf+SCUM_SYNC_REQ_LEN+SCUM_MSG_COUNT_LEN, SCUM_KEY_COUNT_LEN);

  // Clear data
  memset(session->sync_bytes, 0, SCUM_SYNC_REQ_LEN);

  // Update sync session status
  session->status = S_IDLE;

  // Update data session
  data_session->status = S_IDLE;
  ret = scum_derive_keys(&data_session->crypto);
  if (ret != 0) {
    mbedtls_printf("Post-sync key derivation failed");
    return -4;
  }

  return 1;
}



////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                           External Functions                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////



// Setup SCUM context
void scum_setup(struct scum_ctx *ctx, char *sync_key, char *sync_salt, char *data_key, char *data_salt, char *app_buf, char *rad_buf, unsigned char sync)
{
  int ret;

  ret = scum_data_setup(&ctx->data_session, data_key, data_salt, app_buf, rad_buf);
  if (ret != 0) {
    mbedtls_printf("Failed to initialize SCUM data session");
  }

  ret = scum_sync_setup(&ctx->sync_session, sync_key, sync_salt, rad_buf);
  if (ret != 0) {
    mbedtls_printf("Failed to initialize SCUM sync session");
  }

  // Force-sync
  if (sync == 1) {
    ctx->synced = 1;
    ctx->data_session.status = S_IDLE;
  }
}

// Initialize SCUM session states to prevent un-keyed handling
void scum_init(struct scum_ctx *ctx)
{
  // Set unsynced
  ctx->synced = 0;

  // Set sessions as empty
  ctx->data_session.status = S_UNSYNC;
  ctx->sync_session.status = S_UNSYNC;

  // Clear crypto contexts
  mbedtls_gcm_init(&ctx->data_session.crypto.gcm);
  mbedtls_aes_init(&ctx->data_session.crypto.aes);
  memset(ctx->data_session.crypto.m_salt, 0, S_SALT_LEN);
  memset(ctx->data_session.crypto.e_salt, 0, S_SALT_LEN);

  mbedtls_gcm_init(&ctx->sync_session.crypto.gcm);
  mbedtls_aes_init(&ctx->sync_session.crypto.aes);
  memset(ctx->sync_session.crypto.m_salt, 0, S_SALT_LEN);
  memset(ctx->sync_session.crypto.e_salt, 0, S_SALT_LEN);
}

// Receive a SCUM message
void scum_handle(struct scum_ctx *ctx, scewl_id_t src_id, char *data_buf, size_t data_len)
{
  struct scum_hdr *hdr;
  int ret;
  
  ret = scum_check_frame(data_buf, data_len);
  if (ret != 0) {
    mbedtls_printf("Received bad SCUM header");
    return;
  }

  // Get header
  hdr = (struct scum_hdr *)data_buf;

  // Determine correct handling method
  switch (hdr->type) {
    case S_SYNC_REQ:
      ret = scum_sync_req_handle(&ctx->sync_session, &ctx->data_session);
      if (ret != 0) {
        mbedtls_printf("Failed to handle sync request");
      } else {
        mbedtls_printf("Sync request successfully handled");
      }
      break;
    case S_SYNC_RESP:
      ret = scum_sync_resp_receive(&ctx->sync_session, &ctx->data_session);
      if (ret < 0) {
        mbedtls_printf("Failed to handle sync response"); // May have been response to other SED SYNC_REQ
      } else if (ret == 1) {
        ctx->synced = 1;
        mbedtls_printf("Synchronized to SCUM data session");
      }
      break;
    case S_DATA:
      ret = scum_data_receive(&ctx->data_session, src_id);
      if (ret != 0) {
        mbedtls_printf("Failed to handle data");
      }
      break;
  }
}

// Send a SCUM message
void scum_send(struct scum_ctx *ctx, size_t data_len)
{
  int ret;

  ret = scum_data_send(&ctx->data_session, data_len);
  if (ret != 0) {
    mbedtls_printf("Failed to send data");
  }
}

// Synchronize to SCUM network
void scum_sync(struct scum_ctx *ctx)
{
  int ret;

  ret = scum_sync_req_send(&ctx->sync_session);
  if (ret != 0) {
    mbedtls_printf("Failed to send sync request");
  }
}