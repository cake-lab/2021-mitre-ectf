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

#include "scewl.h"
#include "sed_rand.h"
#include "flash_buffers.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include <stdint.h>


/*
 * Definitions
 */

// Secrets
#define S_KEY_LEN (256/8)
#define S_SALT_LEN (96/8)

// Cipher properties
#define CIPHER_BLOCK_LEN (128/8)

#define SCUM_IV_LEN (96/8)
#define SCUM_TAG_LEN (128/8)
#define SCUM_HDR_LEN (sizeof(struct scum_hdr))
#define SCUM_MAX_DATA_LEN (SCEWL_MTU - SCUM_HDR_LEN - SCUM_TAG_LEN)

#define SCUM_SEQ_NUMBER_LEN (sizeof(uint64_t))
#define SCUM_KEY_COUNT_LEN (sizeof(uint32_t))
#define SCUM_SYNC_REQ_LEN (SCUM_SEQ_NUMBER_LEN)
#define SCUM_SYNC_RESP_LEN (SCUM_SYNC_REQ_LEN+SCUM_SEQ_NUMBER_LEN*2)

// Key parameters
#define FRAMES_PER_MSG (((SCEWL_MAX_DATA_SZ-1)/SCUM_MAX_DATA_LEN)+1) // Round up
#define SCUM_DEFAULT_KDR (2*FRAMES_PER_MSG) // x * 17frames/msg

// Timing requirements
#define SYNC_REQ_TIMEOUT 10000 // 10 seconds
#define ARB_REQ_TIMEOUT 5000 // 5 seconds

/*
 * Custom Types/Structs
 */

// Errors
enum scum_error_type {
  S_FATAL_ERROR = -3,
  S_SOFT_ERROR = -2,
  S_PASS = -1
};

// SCUM message types
enum scum_msg_type {
  S_SYNC_REQ,
  S_SYNC_RESP,
  S_ARB_REQ,
  S_DATA
};

// SCUM communication states
enum scum_status {
  S_ERROR,
  S_UNSYNC,
  S_WAIT_SYNC,
  S_IDLE,
  S_ARBITRATING,
  S_RECV_WAIT,
  S_RECV,
  S_DISCARD,
  S_SUCCESS,
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
  struct scum_crypto crypto;

  scewl_id_t recv_src_id;

  uint64_t seq_number;

  uint8_t arbitration_lost;
  uint8_t defeated_dev_count;
  scewl_id_t defeated_ids[MAX_SEDS];

  uint16_t in_received;
  uint16_t out_remaining;
  uint16_t out_msg_len;

  char *stage_buf;
  struct flash_buf *app_fbuf;
};

// SCUM sync session context
struct scum_sync_session {
  struct scum_crypto crypto;

  char *stage_buf;
  
  mbedtls_hmac_drbg_context rng;
  uint8_t sync_bytes[SCUM_SYNC_REQ_LEN];
};

struct scum_ctx {
  enum scum_status status;
  char stage_buf[SCEWL_MTU];
  struct scum_data_session data_session;
  struct scum_sync_session sync_session;
};


/*
 * Function Prototypes
 */

void scum_setup(struct scum_ctx *ctx, char *sync_key, char *sync_salt, char *data_key, char *data_salt, struct flash_buf *app_fbuf, unsigned char sync);
void scum_init(struct scum_ctx *ctx);
void scum_handle(struct scum_ctx *ctx, scewl_id_t src_id, char *data, size_t data_len);
void scum_send(struct scum_ctx *ctx, char *data, size_t data_len);
void scum_sync(struct scum_ctx *ctx);
void scum_arbitrate(struct scum_ctx *ctx);
void scum_arbitrate_continue(struct scum_ctx *ctx);
void scum_timeout(struct scum_ctx *ctx, char *data, size_t data_len);

#endif // BROADCAST_H