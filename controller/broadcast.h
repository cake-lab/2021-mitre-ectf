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

#ifndef BROADCAST_H
#define BROADCAST_H

#include "controller.h"
#include "sed_rand.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include <stdint.h>


/*
 * Definitions
 */

#define MAX_SCEWL_LEN 0x4000

// Secrets
#define S_KEY_LEN (256/8)
#define S_SALT_LEN (96/8)

// Cipher properties
#define CIPHER_BLOCK_LEN (128/8)

// SCUM fields and limits
#define SCUM_MTU 1000

#define SCUM_IV_LEN (96/8)
#define SCUM_TAG_LEN (128/8)
#define SCUM_HDR_LEN (sizeof(struct scum_hdr))
#define SCUM_MAX_DATA_LEN (SCUM_MTU - SCUM_HDR_LEN - SCUM_TAG_LEN)

#define SCUM_MSG_COUNT_LEN (sizeof(uint64_t))
#define SCUM_KEY_COUNT_LEN (sizeof(uint32_t))
#define SCUM_SYNC_REQ_LEN (SCUM_MSG_COUNT_LEN+SCUM_KEY_COUNT_LEN)
#define SCUM_SYNC_RESP_LEN (2*SCUM_SYNC_REQ_LEN)

// Key parameters
#define FRAMES_PER_MSG (MAX_SCEWL_LEN/SCUM_MAX_DATA_LEN)
#define SCUM_DEFAULT_KDR (1000*FRAMES_PER_MSG) // x * 17frames/msg

/*
 * Custom Types/Structs
 */

// SCUM channel types
enum scum_channel_type {
  S_DATA_CHANNEL,
  S_SYNC_CHANNEL
};

// SCUM message types
enum scum_msg_type {
  S_SYNC_REQ,
  S_SYNC_RESP,
  S_DATA
};

// SCUM communication states
enum scum_status {
  S_UNSYNC,
  S_IDLE,
  S_SYNC,
  S_SEND,
  S_RECV,
  S_DONE
};

// SCUM message header
struct scum_hdr {
  uint8_t end_marker;
  uint8_t type;
  uint16_t length;
  uint64_t seq_number;
};

// SCUM crypto context
struct scum_crypto {
  mbedtls_gcm_context gcm;
  mbedtls_aes_context aes;

  uint8_t m_salt[S_SALT_LEN];
  uint8_t e_salt[S_SALT_LEN+(CIPHER_BLOCK_LEN-S_SALT_LEN)]; // Need to suport full block output
  
  uint32_t key_count;
  uint32_t kdr;
};

// SCUM data session context
struct scum_data_session {
  enum scum_status status;
  struct scum_crypto crypto;

  scewl_id_t recv_src_id;

  uint64_t msg_count;

  uint16_t in_received;
  uint16_t out_remaining;
  uint16_t out_msg_len;

  char *app_buf;
  char *rad_buf;
};

// SCUM sync session context
struct scum_sync_session {
  enum scum_status status;
  struct scum_crypto crypto;

  char *rad_buf;
  
  mbedtls_hmac_drbg_context rng;
  uint8_t sync_bytes[SCUM_SYNC_REQ_LEN];
};

struct scum_ctx {
  unsigned char synced;
  struct scum_data_session data_session;
  struct scum_sync_session sync_session;
};


/*
 * Function Prototypes
 */

void scum_setup(struct scum_ctx *ctx, char *sync_key, char *sync_salt, char *data_key, char *data_salt, char *app_buf, char *rad_buf, unsigned char sync);
void scum_init(struct scum_ctx *ctx);
void scum_handle(struct scum_ctx *ctx, scewl_id_t src_id, char *data_buf, size_t data_len);
void scum_send(struct scum_ctx *ctx, size_t data_len);
void scum_sync(struct scum_ctx *ctx);

#endif // BROADCAST_H