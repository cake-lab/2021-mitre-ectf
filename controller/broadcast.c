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
#include "timers.h"
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
    return S_SOFT_ERROR;
  } else if (data_len > SCEWL_MTU) {
    mbedtls_printf("Incoming SCEWL data longer than SCEWL MTU");
    return S_SOFT_ERROR;
  } else if (SCUM_HDR_LEN + hdr->length + SCUM_TAG_LEN != data_len) {
    mbedtls_printf("Incoming SCUM and SCEWL lengths are not compatible");
    return S_SOFT_ERROR;
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
    return S_FATAL_ERROR;
  }
  // Derive key block 1
  iv_buf[15] ^= 0x01;
  ret = mbedtls_aes_crypt_ecb(&crypto->aes, MBEDTLS_AES_ENCRYPT, iv_buf, key_buf+CIPHER_BLOCK_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_crypt_ecb returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }

  // Derive salt
  iv_buf[15] ^= 0x01; // Clear key block counter
  iv_buf[9] ^= 0x02; // Salt type ID
  ret = mbedtls_aes_crypt_ecb(&crypto->aes, MBEDTLS_AES_ENCRYPT, iv_buf, crypto->e_salt);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_aes_crypt_ecb returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }
  memset(crypto->e_salt+S_SALT_LEN, 0, CIPHER_BLOCK_LEN-S_SALT_LEN); // Only 12 bytes

  // Update session key
  ret = mbedtls_gcm_setkey(&crypto->gcm, MBEDTLS_CIPHER_ID_AES, key_buf, S_KEY_LEN*8);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_gcm_setkey returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }

  crypto->key_count++;

  return 0;
}

// Check key status and refresh -- helper function avoids always buffers
static int scum_update_keys(struct scum_crypto *crypto, uint64_t seq_number, uint8_t force)
{
  int ret;

  // Force a re-key from the last kdr multiple (useful for catching up to a running session)
  // Otherwise, only re-key at the key derivation rate
  // CANNOT force if kdr is 0
  if (force && (crypto->kdr != 0)) {
    crypto->key_count = seq_number / crypto->kdr;
  } else if ((crypto->kdr == 0) || (seq_number % crypto->kdr != 0)) {
    return 0;
  }

  ret = scum_derive_keys(crypto);
  if (ret != 0) {
    mbedtls_printf("Key refresh failed");
    return ret;
  }

  return 0;
}


/*
 *
 * SCUM Setup / Initialization
 *
 */

// Clear SCUM crypto context
static void scum_crypto_init(struct scum_crypto *crypto)
{
  // Clear variables
  crypto->key_count = 0;
  crypto->kdr = 0;
  memset(crypto->m_salt, 0, S_SALT_LEN);
  memset(crypto->e_salt, 0, S_SALT_LEN+(CIPHER_BLOCK_LEN-S_SALT_LEN));

  // Initialize contexts
  mbedtls_gcm_init(&crypto->gcm);
  mbedtls_aes_init(&crypto->aes);
}

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
    return S_FATAL_ERROR;
  }

  // Load PRF salt
  memcpy(crypto->m_salt, salt, S_SALT_LEN);

  // Derive session key
  ret = scum_derive_keys(crypto);
  if (ret != 0) {
    mbedtls_printf("Key initialization failed");
    return ret;
  }

  return 0;
}

// Clear SCUM data session
static void scum_data_init(struct scum_data_session *session)
{
  // Clear crypto state
  scum_crypto_init(&session->crypto);

  // Clear variables
  session->seq_number = 0;
  session->in_received = 0;
  session->out_remaining = 0;
  session->out_msg_len = 0;
  session->recv_src_id = 0;
  session->arbitration_lost = 0;
  session->arbitrated_dev_count = 0;
  session->stage_buf = NULL;
  session->app_fbuf = NULL;
}

// Setup SCUM data session
static int scum_data_setup(struct scum_data_session *session, char *key, char *salt, char *stage_buf, struct flash_buf *app_fbuf)
{
  int ret;

  // Initialize session parameters
  session->seq_number = 0;
  session->in_received = 0;
  session->out_remaining = 0;
  session->out_msg_len = 0;
  session->recv_src_id = 0;
  session->arbitration_lost = 0;
  session->arbitrated_dev_count = 0;
  session->stage_buf = stage_buf;
  session->app_fbuf = app_fbuf;

  // Set up crypto context
  ret = scum_crypto_setup(&session->crypto, key, salt, SCUM_DEFAULT_KDR);
  if (ret != 0) {
    mbedtls_printf("Data session key setup failed");
    return ret;
  }

  return 0;
}

// Clear SCUM sync session
static void scum_sync_init(struct scum_sync_session *session)
{
  // Clear crypto state
  scum_crypto_init(&session->crypto);

  // Clear variables
  session->stage_buf = NULL;
  memset(session->sync_bytes, 0, SCUM_SYNC_REQ_LEN);

  // Initialize primitives
  mbedtls_hmac_drbg_init(&session->rng);
}

// Setup SCUM sync session
static int scum_sync_setup(struct scum_sync_session *session, char *key, char *salt, char *stage_buf)
{
  int ret;

  // Initialize session parameters
  session->stage_buf = stage_buf;

  // Initialize primitives
  mbedtls_hmac_drbg_init(&session->rng);
  ret = rng_setup(&session->rng, NULL, 0);
  if (ret != 0) {
    mbedtls_printf("Sync session RNG setup failed");
    return S_FATAL_ERROR;
  }

  // Set up crypto context
  ret = scum_crypto_setup(&session->crypto, key, salt, 0);
  if (ret != 0) {
    mbedtls_printf("Sync session key setup failed");
    return ret;
  }

  return 0;
}

// Kill SCUM state
static void scum_fatal_error(struct scum_ctx *ctx) {
  // Clear state
  scum_init(ctx);
  // Set error state
  ctx->status = S_ERROR;
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
    return S_FATAL_ERROR;
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
    return S_SOFT_ERROR;
  }

  return hdr->length;
}


/*
 *
 * Data Session Operations
 *
 */


// Send next data frame from app buffer to radio buffer
static int scum_data_push(struct scum_data_session *session, char *data)
{
  struct scum_hdr *hdr;
  int ret;

  // Construct header in output buffer
  hdr = (struct scum_hdr *)session->stage_buf;
  hdr->type = S_DATA;
  hdr->seq_number = session->seq_number;

  if (session->out_remaining <= SCUM_MAX_DATA_LEN) {
    hdr->length = session->out_remaining;
    hdr->end_marker = 1;
  } else {
    hdr->length = SCUM_MAX_DATA_LEN;
    hdr->end_marker = 0;
  }

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, data, session->stage_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to send SCUM frame");
    return ret;
  }

  // Update stream status
  session->out_remaining -= ret;

  // Update session status
  session->seq_number++;

  // Refresh keys if needed
  ret = scum_update_keys(&session->crypto, session->seq_number, 0/*no force*/);
  if (ret != 0) {
    mbedtls_printf("Data session (send) key refresh failed");
    return ret;
  }

  // Return stream status
  return hdr->end_marker;
}

// Process outgoing broadcast message
static int scum_data_send(struct scum_ctx *ctx, char *data, size_t data_len)
{ 
  struct scum_data_session *session;
  int ret;

  session = &ctx->data_session;

  // Start new data stream if not being used (unsynced state will bypass)
  // Should have already arbitrated
  if (ctx->status == S_ARBITRATING) {
    session->out_remaining = data_len;
    session->out_msg_len = data_len;

    do {
      ret = scum_data_push(session, data+(session->out_msg_len-session->out_remaining));
      if (ret < 0) {
        mbedtls_printf("Failed to push SCUM data frame");
        ctx->status = S_IDLE;
        return ret;
      }
    } while (ret != 1);
    ctx->status = S_DONE;
  }
  if (ctx->status == S_DONE) {
    mbedtls_printf("Sent broadcast: %.*s", session->out_msg_len, data);

    // If SED beat other devices during arbitration, give them a chance to send
    if (session->arbitrated_dev_count > 0) {
      ctx->status = S_RECV_WAIT;
    } else {
      ctx->status = S_IDLE;
    }
  }

  return 0;
}

// Receive next data frame from radio buffer into app buffer
static int scum_data_absorb(struct scum_data_session *session, char *data)
{
  struct scum_hdr *hdr;
  int ret;

  // Get header
  hdr = (struct scum_hdr *)data;

  // Make sure message can fit and is in sequence
  if (hdr->length + session->in_received > SCEWL_MAX_DATA_SZ) {
    mbedtls_printf("Attempted to receive more than SCEWL_MAX_DATA_SZ bytes");
    return S_SOFT_ERROR;
  } else if (hdr->seq_number < session->seq_number) {
    mbedtls_printf("Attempted to receive message with earlier sequence number");
    return S_SOFT_ERROR;
  }

  // Decrypt and absorb
  ret = scum_absorb_frame(&session->crypto, data, session->stage_buf);

  // If authentication failed and message count is from the future,
  // temporarily update key and retry -- revert keys on second failure
  // If any other errors occur during this, exit as normal
  if (ret < 0 && ret != S_SOFT_ERROR) {

    mbedtls_printf("Failed to decrypt SCUM frame");
    return ret;

  } else if ((ret == S_SOFT_ERROR) && (hdr->seq_number > session->seq_number)) {

    mbedtls_printf("Failed to decrypt SCUM frame -- retrying with updated keys");
    ret = scum_update_keys(&session->crypto, hdr->seq_number, 1/*force*/);
    if (ret != 0) {
      mbedtls_printf("Data session (receive) temporary key refresh failed");
      return ret;
    }

    ret = scum_absorb_frame(&session->crypto, data, session->stage_buf);
    if (ret < 0) {
      mbedtls_printf("Failed to decrypt SCUM frame with updated keys -- reverting");
      ret = scum_update_keys(&session->crypto, session->seq_number, 1/*force*/);
      if (ret != 0) {
        mbedtls_printf("Data session (receive) key revert failed");
        return ret;
      }
      return ret;
    }

    mbedtls_printf("SCUM frame decryption successful with updated keys -- keeping them");
  }

  // Write to SCUM flash buffer -- if have received no bytes yet, request an erase
  flash_write_buf(session->app_fbuf, session->stage_buf, ret, (session->in_received == 0 ? 1 : 0));

  // Update stream status
  session->in_received += ret;

  // Update session status (next message is 1 count higher than this one)
  session->seq_number = hdr->seq_number+1;

  // Refresh keys if needed
  ret = scum_update_keys(&session->crypto, session->seq_number, 0/*no force*/);
  if (ret != 0) {
    mbedtls_printf("Data session (receive) key refresh failed");
    return ret;
  }

  // Return stream status
  return hdr->end_marker;
}

// Process incoming broadcast message
static int scum_data_receive(struct scum_ctx *ctx, scewl_id_t src_id, char *data)
{
  struct scum_data_session *session;
  int ret;

  session = &ctx->data_session;

  // Start new data stream or continue current one (unsynced state will bypass)
  // Should have already witnessed arbitration
  if (ctx->status == S_RECV_WAIT) {
    session->recv_src_id = src_id;
    session->in_received = 0;
    ctx->status = S_RECV;
  }
  if (ctx->status == S_RECV) {
    // Check the same SED is broadcasting
    if (src_id != session->recv_src_id) {
      mbedtls_printf("Ignoring broadcast from ID %d during broadcast from ID %d", src_id, session->recv_src_id);
      return 0;
    }

    // Handle the frame - check for error or end marker
    ret = scum_data_absorb(session, data);
    if (ret < 0) {
      mbedtls_printf("Failed to absorb SCUM data frame");
      ctx->status = S_IDLE;
      return ret;
    } else if (ret == 1) {
      flash_commit_buf(session->app_fbuf);
      ctx->status = S_DONE;
    }
  }
  if (ctx->status == S_DONE) {
    // Send to CPU
    handle_brdcst_recv(flash_get_buf(session->app_fbuf), session->recv_src_id, session->in_received);
    mbedtls_printf("Received broadcast from %d: %.*s", session->recv_src_id, session->in_received, flash_get_buf(session->app_fbuf));

    // Continue to let other devices send if you beat them
    if (session->arbitrated_dev_count > 1) {
      session->arbitrated_dev_count--;
      mbedtls_printf("%d devices from my arbitration have yet to send", session->arbitrated_dev_count);
      ctx->status = S_RECV_WAIT;
    } else {
      session->arbitrated_dev_count = 0;
      ctx->status = S_IDLE;
    }

    // Try sending message if blocked last time
    if (session->arbitration_lost == 1) {
      mbedtls_printf("Trying to send pending message");
      scum_arbitrate(ctx);
      scum_arbitrate_continue(ctx);
    }
  }

  return 0;
}


/*
 *
 * Arbitration Operations
 *
 */

// Process outgoing arbitration request
static int scum_arb_req_send(struct scum_ctx *ctx)
{
  struct scum_sync_session *session;
  struct scum_data_session *data_session;
  struct scum_hdr *hdr;
  int ret;

  session = &ctx->sync_session;
  data_session = &ctx->data_session;

  // Proceed if not doing anything
  if (ctx->status != S_IDLE) {
    mbedtls_printf("Refusing to send an arbitration request while doing something else");
    return S_PASS;
  }

  // Construct header in output buffer
  hdr = (struct scum_hdr *)session->stage_buf;
  hdr->type = S_ARB_REQ;
  hdr->seq_number = 0;
  hdr->length = SCUM_SYNC_REQ_LEN;
  hdr->end_marker = 1;

  // Create random message
  ret = mbedtls_hmac_drbg_random(&session->rng, session->sync_bytes, SCUM_SYNC_REQ_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_hmac_drbg_random returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, (char *)session->sync_bytes, session->stage_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to send sync request frame");
    return ret;
  }

  // Update status
  ctx->status = S_ARBITRATING;
  data_session->arbitration_lost = 0;
  data_session->arbitrated_dev_count = 0;

  mbedtls_printf("Sent arbitration request");

  return 0;
}

// Process incoming arbitration request
static int scum_arb_req_receive(struct scum_ctx *ctx, scewl_id_t src_id, char *data)
{
  struct scum_sync_session *sync_session;
  struct scum_data_session *data_session;
  struct scum_hdr *hdr;
  uint8_t msg_buf[SCUM_SYNC_REQ_LEN];
  int ret;

  sync_session = &ctx->sync_session;
  data_session = &ctx->data_session;

  // Get header
  hdr = (struct scum_hdr *)data;

  // Only handle request when idle or doing arbitration
  if (ctx->status != S_IDLE && ctx->status != S_ARBITRATING) {
    mbedtls_printf("Ignoring arbitration request message");
    return S_PASS;
  }

  // Check message length
  if (hdr->length != SCUM_SYNC_REQ_LEN) {
    mbedtls_printf("Got an arbitration request with invalid message length");
    return S_SOFT_ERROR;
  }

  // Decrypt
  ret = scum_absorb_frame(&sync_session->crypto, data, (char *)msg_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return ret;
  }

  // If trying to arbitrate, relinquish control if you have the higher ID
  if (ctx->status == S_ARBITRATING) {
    if (src_id < SCEWL_ID) {
      mbedtls_printf("Relinquish to device %d", src_id);
      // Give up on sending
      timers_clear_scum_timeout();
      data_session->arbitration_lost = 1;
      data_session->arbitrated_dev_count = 0;
      ctx->status = S_RECV_WAIT;
    } else {
      // Keep track of every device you beat
      mbedtls_printf("Defeated device %d", src_id);
      data_session->arbitrated_dev_count++;
    }
  } else if (ctx->status != S_ERROR) {
    // If not arbitrating, accept any request and start waiting for the data
    mbedtls_printf("Waiting for device %d", src_id);
    ctx->status = S_RECV_WAIT;
  }

  return 0;
}


/*
 *
 * Sync Session Operations
 *
 */

// Process outgoing sync request
static int scum_sync_req_send(struct scum_ctx *ctx)
{
  struct scum_sync_session *session;
  struct scum_hdr *hdr;
  int ret;

  session = &ctx->sync_session;

  // Proceed if not disabled
  if (ctx->status == S_ERROR) {
    mbedtls_printf("Refusing to send a sync request while in error state");
    return S_PASS;
  }

  // Construct header in output buffer
  hdr = (struct scum_hdr *)session->stage_buf;
  hdr->type = S_SYNC_REQ;
  hdr->seq_number = 0;
  hdr->length = SCUM_SYNC_REQ_LEN;
  hdr->end_marker = 1;

  // Create random message
  ret = mbedtls_hmac_drbg_random(&session->rng, session->sync_bytes, SCUM_SYNC_REQ_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_hmac_drbg_random returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }

  // Encrypt and send
  ret = scum_push_frame(&session->crypto, (char *)session->sync_bytes, session->stage_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to send sync request frame");
    return ret;
  }

  // Update status
  ctx->status = S_WAIT_SYNC;

  // Setup hardware timer
  timers_set_scum_timeout(SYNC_REQ_TIMEOUT);

  return 0;
}

// Process incoming sync request
static int scum_sync_req_handle(struct scum_ctx *ctx, char *data)
{
  struct scum_sync_session *sync_session;
  struct scum_data_session *data_session;
  struct scum_hdr *hdr;
  uint8_t msg_buf[SCUM_SYNC_RESP_LEN];
  int ret;

  sync_session = &ctx->sync_session;
  data_session = &ctx->data_session;

  // Get header
  hdr = (struct scum_hdr *)data;

  // Only handle request when idle
  if (ctx->status != S_IDLE) {
    mbedtls_printf("Ignoring sync request message");
    return S_PASS;
  }

  // Check message length
  if (hdr->length != SCUM_SYNC_REQ_LEN) {
    mbedtls_printf("Got a sync request with invalid message length");
    return S_SOFT_ERROR;
  }

  // Decrypt
  ret = scum_absorb_frame(&sync_session->crypto, data, (char *)msg_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return ret;
  }

  // Generate random mask
  ret = mbedtls_hmac_drbg_random(&sync_session->rng, msg_buf+SCUM_SYNC_REQ_LEN, SCUM_SEQ_NUMBER_LEN);
  if (ret != 0) {
    mbedtls_printf("failed! mbedtls_hmac_drbg_random returned -%#06x", (unsigned int) -ret);
    return S_FATAL_ERROR;
  }

  // Copy random mask into last section
  memcpy(msg_buf+SCUM_SYNC_REQ_LEN+SCUM_SEQ_NUMBER_LEN, msg_buf+SCUM_SYNC_REQ_LEN, SCUM_SEQ_NUMBER_LEN);

  // XOR sequence count into copy of random mask
  for (int i = 0; i < SCUM_SEQ_NUMBER_LEN; i++) {
    *(msg_buf+SCUM_SYNC_REQ_LEN+SCUM_SEQ_NUMBER_LEN+i) ^= *(((uint8_t *)&data_session->seq_number)+i);
  }

  // Construct outgoing header
  hdr = (struct scum_hdr *)sync_session->stage_buf;
  hdr->type = S_SYNC_RESP;
  hdr->seq_number = 0;
  hdr->length = SCUM_SYNC_RESP_LEN;
  hdr->end_marker = 1;

  // Encrypt and send
  ret = scum_push_frame(&sync_session->crypto, (char *)msg_buf, sync_session->stage_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to send SCUM frame");
    return ret;
  }

  return 0;
}

// Process incoming sync response
static int scum_sync_resp_receive(struct scum_ctx *ctx, char *data)
{
  struct scum_sync_session *sync_session;
  struct scum_data_session *data_session;
  struct scum_hdr *hdr;
  uint8_t msg_buf[SCUM_SYNC_RESP_LEN];
  int ret;

  sync_session = &ctx->sync_session;
  data_session = &ctx->data_session;

  // Check sync session isn't running
  if (ctx->status != S_WAIT_SYNC) {
    mbedtls_printf("Ignoring sync response message");
    return S_PASS;
  }

  // Get header
  hdr = (struct scum_hdr *)data;

  // Check message length
  if (hdr->length != SCUM_SYNC_RESP_LEN) {
    mbedtls_printf("Got a synq response with invalid message length");
    return S_SOFT_ERROR;
  }

  // Decrypt
  ret = scum_absorb_frame(&sync_session->crypto, data, (char *)msg_buf);
  if (ret < 0) {
    mbedtls_printf("Failed to decrypt SCUM frame");
    return ret;
  }

  // Check random bytes match
  ret = memcmp(msg_buf, sync_session->sync_bytes, SCUM_SYNC_REQ_LEN);
  if (ret != 0) {
    mbedtls_printf("Received incorrect sync bytes in synq response");
    return S_SOFT_ERROR;
  }

  // Clear timeout
  timers_clear_scum_timeout();

  // Remove random mask from sequence count
  for (int i = 0; i < SCUM_SEQ_NUMBER_LEN; i++) {
    *(msg_buf+SCUM_SYNC_REQ_LEN+SCUM_SEQ_NUMBER_LEN+i) ^= *(msg_buf+SCUM_SYNC_REQ_LEN+i);
  }

  // Copy sequence count
  memcpy((uint8_t *)&data_session->seq_number, msg_buf+SCUM_SYNC_REQ_LEN+SCUM_SEQ_NUMBER_LEN, SCUM_SEQ_NUMBER_LEN);

  // Clear data
  memset(sync_session->sync_bytes, 0, SCUM_SYNC_REQ_LEN);

  // Update status
  ctx->status = S_IDLE;

  // Update data session
  ret = scum_update_keys(&data_session->crypto, data_session->seq_number, 1/*force*/);
  if (ret != 0) {
    mbedtls_printf("Post-sync key derivation failed");
    return ret;
  }

  return 0;
}



////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                           External Functions                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////



// Initialize SCUM session states to prevent un-keyed handling
void scum_init(struct scum_ctx *ctx)
{
  // Set session as unsynced
  ctx->status = S_UNSYNC;

  // Clear staging buf
  memset(ctx->stage_buf, 0, SCEWL_MTU);

  // Clear sessions
  scum_data_init(&ctx->data_session);
  scum_sync_init(&ctx->sync_session);
}

// Setup SCUM context
void scum_setup(struct scum_ctx *ctx, char *sync_key, char *sync_salt, char *data_key, char *data_salt, struct flash_buf *app_fbuf, unsigned char sync)
{
  int ret;

  // Force-sync
  if (sync == 1) {
    ctx->status = S_IDLE;
  } else {
    ctx->status = S_UNSYNC;
  }

  ret = scum_data_setup(&ctx->data_session, data_key, data_salt, ctx->stage_buf, app_fbuf);
  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Failed to initialize SCUM data session");
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Fatal error initializing SCUM data session");
    scum_fatal_error(ctx);
  }

  ret = scum_sync_setup(&ctx->sync_session, sync_key, sync_salt, ctx->stage_buf);
  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Failed to initialize SCUM sync session");
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Fatal error initializaing SCUM sync session");
    scum_fatal_error(ctx);
  }
}

// Receive a SCUM message
void scum_handle(struct scum_ctx *ctx, scewl_id_t src_id, char *data, size_t data_len)
{
  struct scum_hdr *hdr;
  int ret;
  
  ret = scum_check_frame(data, data_len);
  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Received bad SCUM header");
    return;
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Received critically bad SCUM header");
    scum_fatal_error(ctx);
    return;
  }

  // Get header
  hdr = (struct scum_hdr *)data;

  // Determine correct handling method
  switch (hdr->type) {
    case S_SYNC_REQ:
      ret = scum_sync_req_handle(ctx, data);
      if (ret == S_SOFT_ERROR) {
        mbedtls_printf("Failed to handle sync request");
      } else if (ret == S_FATAL_ERROR) {
        mbedtls_printf("Fatal error handling sync request");
        scum_fatal_error(ctx);
      } else if (ret != S_PASS) {
        mbedtls_printf("Sync request successfully handled");
      }
      break;
    case S_SYNC_RESP:
      ret = scum_sync_resp_receive(ctx, data);
      if (ret == S_SOFT_ERROR) {
        mbedtls_printf("Failed to handle sync response"); // May have been response to other SED or old sync request
      } else if (ret == S_FATAL_ERROR) {
        mbedtls_printf("Fatal error handling sync response");
        scum_fatal_error(ctx);
      } else if (ret != S_PASS) {
        mbedtls_printf("Synchronized to SCUM data session");
      }
      break;
    case S_ARB_REQ:
      ret = scum_arb_req_receive(ctx, src_id, data);
      if (ret == S_SOFT_ERROR) {
        mbedtls_printf("Failed to handle arbitration request");
      } else if (ret == S_FATAL_ERROR) {
        mbedtls_printf("Fatal error handling arbitration request");
        scum_fatal_error(ctx);
      }
      break;
    case S_DATA:
      ret = scum_data_receive(ctx, src_id, data);
      if (ret == S_SOFT_ERROR) {
        mbedtls_printf("Failed to handle data");
      } else if (ret == S_FATAL_ERROR) {
        mbedtls_printf("Fatal error handling data");
        scum_fatal_error(ctx);
      }
      break;
  }
}

// Send a SCUM message
void scum_send(struct scum_ctx *ctx, char *data, size_t data_len)
{
  int ret;

  ret = scum_data_send(ctx, data, data_len);
  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Failed to send data");
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Fatal error sending data");
    scum_fatal_error(ctx);
  }
}

// Synchronize to SCUM network
void scum_sync(struct scum_ctx *ctx)
{
  int ret;

  ret = scum_sync_req_send(ctx);
  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Failed to send sync request");
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Fatal error sending sync request");
    scum_fatal_error(ctx);
  }
}

// Request control of broadcast system
void scum_arbitrate(struct scum_ctx *ctx)
{
  int ret;
  ret = scum_arb_req_send(ctx);

  if (ret == S_SOFT_ERROR) {
    mbedtls_printf("Failed to arbitration request");
  } else if (ret == S_FATAL_ERROR) {
    mbedtls_printf("Fatal error sending arbitration request");
    scum_fatal_error(ctx);
  }
}

// Start timer for arbitration phase
void scum_arbitrate_continue(struct scum_ctx *ctx)
{

  if (ctx->status == S_ARBITRATING) {
    // Setup hardware timer
    timers_set_scum_timeout(SYNC_REQ_TIMEOUT);
  } else {
    mbedtls_printf("Cannot set arbitration timeout if a request has not been sent");
  }
}

// Handle a SCUM sync timeout
void scum_timeout(struct scum_ctx *ctx, char *data, size_t data_len)
{
  // Handle sync timeout or arbitration timeout
  if (ctx->status == S_WAIT_SYNC) {
    scum_sync(ctx);
  } else if (ctx->status == S_ARBITRATING) {
    mbedtls_printf("Won arbitration against %d devices. Sending message", ctx->data_session.arbitrated_dev_count);
    ctx->data_session.arbitration_lost = 0;
    scum_send(ctx, data, data_len);
  }
}