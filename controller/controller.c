/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller implementation
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#include <stdarg.h>
#include "controller.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "broadcast.h"
#include "masked_aes.h"
#include "timers.h"

// Cannot include printf.h because it contains preprocessor defines that cause problems
// These functions are defined in printf.c
int snprintf_(char *buffer, size_t count, const char *format, ...);
int vsnprintf_(char *buffer, size_t count, const char *format, va_list va);

#define send_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)
#define MAX_PRINTF_LENGTH 1000


// Globals
static struct scum_ctx *scum_ctx_ref;
mbedtls_hmac_drbg_context *aes_hmac_drbg_ref;
char *cpu_buf_ref;
char *scewl_buf_ref;
static bool registered;


// Backup SCEWL_MAX_DATA_SZ-sized buffer to the end of flash
// Each protocol has its own dedicated segment
void backup_buf(char *buf, enum proto_type type)
{
  uint32_t start_address;
  
  if (type == DTLS) {
    start_address = DTLS_BACKUP_START;
  } else {
    start_address = SCUM_BACKUP_START;
  }

  // Erase all subsequent pages
  for (uint32_t i = 0; i < PAGES_PER_BUF; i++) {
    FLASH_CTRL->FMA &= ~(FLASH_FMA_OFFSET_M); // Clear address field
    FLASH_CTRL->FMA |= (start_address + (i*PAGE_SIZE)); // Write address field
    FLASH_CTRL->FMC |= (FLASH_FMC_WRKEY | FLASH_FMC_ERASE_M); // Start erase
    while (FLASH_CTRL->FMC & FLASH_FMC_ERASE_M); // Wait until erase bit is 0
  }

  // Write 32-bit words
  for (uint32_t i = 0; i < WORDS_PER_BUF; i++) {
    FLASH_CTRL->FMA &= ~(FLASH_FMA_OFFSET_M); // Clear address field
    FLASH_CTRL->FMA |= (start_address + (i*4)); // Write address field
    FLASH_CTRL->FMD = *((uint32_t *)(buf+i*4)); // Write 32 bits
    FLASH_CTRL->FMC |= (FLASH_FMC_WRKEY | FLASH_FMC_WRITE_M); // Start write
    while (FLASH_CTRL->FMC & FLASH_FMC_WRITE_M); // Wait until write bit is 0
  }
}

// Restore SCEWL_MAX_DATA_SZ-sized buffer from the end of flash
// Each protocol has its own dedicated segment
void restore_buf(char *buf, enum proto_type type)
{
  uint32_t start_address;
  
  if (type == DTLS) {
    start_address = DTLS_BACKUP_START;
  } else {
    start_address = SCUM_BACKUP_START;
  }

  // Copy 32-bit words
  for (uint32_t i = 0; i < WORDS_PER_BUF; i++) {
    *((uint32_t *)(buf+i*4)) = *((uint32_t *)(start_address+i*4));
  }
}

// Read message header only
int read_hdr(intf_t *intf, scewl_hdr_t *hdr, int blocking) {
  int read;

  // clear header
  memset(hdr, 0, sizeof(scewl_hdr_t));

  // find header start
  do {
    hdr->magicC = 0;

    if (intf_read(intf, (char *)&hdr->magicS, 1, blocking) == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // check for SC
    if (hdr->magicS == 'S') {
      do {
        if (intf_read(intf, (char *)&hdr->magicC, 1, blocking) == INTF_NO_DATA) {
          return SCEWL_NO_MSG;
        }
      } while (hdr->magicC == 'S'); // in case of multiple 'S's in a row
    }
  } while (hdr->magicS != 'S' && hdr->magicC != 'C');

  // read rest of header
  read = intf_read(intf, (char *)hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
  if(read == INTF_NO_DATA) {
    return SCEWL_NO_MSG;
  }

  return SCEWL_OK;
}

// Read message body only
int read_body(intf_t *intf, scewl_hdr_t *hdr, char *data, size_t n, int blocking) {
  int read, max;

  // clear buffer and header
  memset(data, 0, n);

  if (intf == SSS_INTF) {
    mbedtls_printf("Packet has payload length %hu.", hdr->len);
  }

  // read body
  max = hdr->len < n ? hdr->len : n;
  read = intf_read(intf, data, max, blocking);

  // throw away rest of message if too long
  for (int i = 0; hdr->len > max && i < hdr->len - max; i++) {
    intf_readb(intf, 0);
  }

  // report if not blocking and full message not received
  if(read == INTF_NO_DATA || read < max) {
    return SCEWL_NO_MSG;
  }

  return max;
}

// Read full message
int read_msg(intf_t *intf, scewl_hdr_t *hdr, char *data, size_t n, int blocking) {
  if (read_hdr(intf, hdr, blocking) == SCEWL_NO_MSG) {
    return SCEWL_NO_MSG;
  }
  return read_body(intf, hdr, data, n, blocking);
}


int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, const char *data) {
  scewl_hdr_t hdr;

  // pack header
  hdr.magicS  = 'S';
  hdr.magicC  = 'C';
  hdr.src_id = src_id;
  hdr.tgt_id = tgt_id;
  hdr.len    = len;

  // send header
  intf_write(intf, (char *)&hdr, sizeof(scewl_hdr_t));

  // send body
  intf_write(intf, data, len);

  return SCEWL_OK;
}


void handle_sss_recv(struct dtls_state *dtls_state, const char* data, uint16_t len) {
  scewl_sss_msg_t *msg;
  const unsigned char *ca, *crt, *key, *sync_key, *sync_salt, *data_key, *data_salt, *first_sed, *entropy;
  uint8_t illegal_len = 0;

  if (len >= sizeof(scewl_sss_msg_t)) {
    msg = (scewl_sss_msg_t *) data;
    if (msg->ca_len + msg->crt_len + msg->key_len + msg->sync_key_len + msg->sync_salt_len + msg->data_key_len + msg->data_salt_len + msg->sync_len + msg->entropy_len == len - sizeof(scewl_sss_msg_t)) {
      switch (msg->op) {
        case SCEWL_SSS_REG:

          // Check for correct SCUM data length
          if (msg->sync_key_len + msg->sync_salt_len + msg->data_key_len + msg->data_salt_len + msg->sync_len + msg->entropy_len != S_KEY_LEN*2 + S_SALT_LEN*2 + 1 + ENTROPY_POOL_SIZE) {
            illegal_len = 1;
            break;
          }

          ca = (const unsigned char *) data + sizeof(scewl_sss_msg_t);
          crt = (const unsigned char *) data + sizeof(scewl_sss_msg_t) + msg->ca_len;
          key = (const unsigned char *) data + sizeof(scewl_sss_msg_t) + msg->ca_len + msg->crt_len;
          sync_key = (const unsigned char *) data + sizeof(scewl_sss_msg_t) + msg->ca_len + msg->crt_len + msg->key_len;
          sync_salt = (const unsigned char *) sync_key + S_KEY_LEN;
          data_key = (const unsigned char *) sync_key + S_KEY_LEN + S_SALT_LEN;
          data_salt = (const unsigned char *) sync_key + S_KEY_LEN*2 + S_SALT_LEN;
          first_sed = (const unsigned char *) sync_key + S_KEY_LEN*2 + S_SALT_LEN*2;
          entropy = (const unsigned char *) sync_key + S_KEY_LEN*2 + S_SALT_LEN*2 + 1;

          dtls_rekey(dtls_state, ca, msg->ca_len, crt, msg->crt_len, key, msg->key_len, true, true);
          registered = true;
          mbedtls_printf("Registered.");

          // Setup runtime RNG state -- happens by default in SCUM
          rng_load_runtime_pool((unsigned char *)entropy, msg->entropy_len);
          dtls_config_runtime_rng(dtls_state);
          Masked_AES_RNG_Setup(aes_hmac_drbg_ref, 1/*runtime*/);

          scum_setup(scum_ctx_ref,
                   (char *)sync_key, (char *)sync_salt,
                   (char *)data_key, (char *)data_salt,
                   cpu_buf_ref, scewl_buf_ref,
                   *first_sed);

          if (!scum_ctx_ref->synced) {
            scum_sync(scum_ctx_ref);
            mbedtls_printf("Sent SCUM sync request...");
          }
          break;
        case SCEWL_SSS_DEREG:
          dtls_rekey_to_default(dtls_state, true, false);
          scum_init(scum_ctx_ref);
          registered = false;
          mbedtls_printf("Deregistered.");
          break;
        default:
          mbedtls_printf("Received response from SSS with invalid status.");
      }
      if (!illegal_len) {
        // forward message to CPU -- clear data except for device ID and op
        const uint16_t cpu_required_len = sizeof(msg->dev_id) + sizeof(msg->op);
        memset((unsigned char *)data+cpu_required_len, 0, len - cpu_required_len);
        send_msg(CPU_INTF, SCEWL_SSS_ID, SCEWL_ID, cpu_required_len, data);
        return;
      }
    }
  }
  mbedtls_printf("Received invalid response from SSS.");
}


int handle_scewl_recv(const char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}


int handle_brdcst_recv(const char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_BRDCST_ID, len, data);
}


int handle_brdcst_send(const char *data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_BRDCST_ID, len, data);
}   


int handle_faa_recv(const char* data, uint16_t len) {
  return send_msg(CPU_INTF, SCEWL_FAA_ID, SCEWL_ID, len, data);
}


int handle_faa_send(const char* data, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, len, data);
}


/*
 * Implementation of exit that works by causing a segmentation fault.
 * Copied from lm3s/startup_gcc.c
 */
void exit(int status) {
  // QEMU doesn't provide a good way to gracefully exit for baremetal apps
  // this is to intentionally crash QEMU with an error like
  // "qemu-system-arm: Trying to execute code outside RAM or ROM at 0x77777776"
  void (*die)(void) = (void (*)(void))0x77777777;
  die();
}

/*
 * Implementation of printf that sends the message over the air as an FAA message.
 */
int printf(const char *format, ...) {
  va_list args;
#ifdef DEBUG_LEVEL
  char message[MAX_PRINTF_LENGTH];
  va_start(args, format);
  int length = vsnprintf_(message, MAX_PRINTF_LENGTH, format, args);
  va_end(args);
  if (length > MAX_PRINTF_LENGTH) {
    length = MAX_PRINTF_LENGTH;
  }
  handle_faa_send(message, length);
  return length;
#else
  return 0;
#endif
}

/*
 * Implementation of putchar that exits the program.
 * This function should never be called but is required by the printf library to link successfully.
 */
void _putchar(char character) {
  exit(1);
}

/*
 * Used by mbedtls to zero memory.
 * This implementation is not secure because it might be optimized out by the compiler.
 * The default, more secure implementation was causing the application to crash.
 */
void mbedtls_platform_zeroize(void *buf, size_t len) {
  memset(buf, 0, len);
}

/*
 * Macro for complicated CPU buf read condition
 * Ignore CPU buf in any of these conditions:
 *    1. Already took CPU reg request
 *    2. Waiting to sync SCUM
 *    3. Registered, synced, and handling some type of message
 */
#define CANT_TAKE_CPU_MSG(reg, synced, dtls, scum) (\
  (!reg && (dtls != IDLE)) || \
  (reg && !synced)         || \
  (reg && synced && ((dtls != IDLE) || (scum == S_RECV)))\
)

int main() {
  struct dtls_state dtls_state;
  // heap memory for mbedtls
  unsigned char memory_buf[30000];
  int len;
  scewl_hdr_t hdr;
  // buffers for CPU and SCEWL packets
  char cpu_buf[SCEWL_MAX_DATA_SZ];
  char scewl_buf[1000];
  struct scum_ctx scum_ctx;
  // RNG for masked AES
  mbedtls_hmac_drbg_context aes_hmac_drbg;

  // Backup status
  unsigned char scum_backed_up = 0, dtls_backed_up = 0;

  // Set global refs
  aes_hmac_drbg_ref = &aes_hmac_drbg;
  scum_ctx_ref = &scum_ctx;
  cpu_buf_ref = cpu_buf;
  scewl_buf_ref = scewl_buf;

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

  // Enable Timer interrupts
  NVIC_EnableIRQ(Timer0A_IRQn);
  NVIC_EnableIRQ(Timer1A_IRQn);

  // Enable global interrupts
  __enable_irq();

  // heap memory for mbedtls
  mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));
  // replacements for stdlib functions for mbedtls
  mbedtls_platform_set_exit(exit);
  mbedtls_platform_set_printf(printf);
  mbedtls_platform_set_snprintf(snprintf_);
  mbedtls_platform_set_vsnprintf(vsnprintf_);
#if defined(MBEDTLS_DEBUG_C) && defined(DEBUG_LEVEL)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
  mbedtls_printf("Hello, world! This is from main.");

  // Set up mask generation
  if (Masked_AES_RNG_Setup(&aes_hmac_drbg, 0/*initial*/) != 0) {
    mbedtls_printf("Error setting up masked AES rng. Entering death loop.");
    while (1);
  }

  // Setup / initialize protocols
  dtls_setup(&dtls_state, cpu_buf);
  scum_init(&scum_ctx);

  // serve forever
  while (1) {

    // Handle final timer expiration
    if (fin_timer_event) {
      fin_timer_event = 0;
      dtls_check_timers(&dtls_state);
    }

    // handle outgoing message from CPU
    if (intf_avail(CPU_INTF)) {
      if (CANT_TAKE_CPU_MSG(registered, scum_ctx.synced, dtls_state.status, scum_ctx.data_session.status)) {
        mbedtls_printf("There is a message waiting on the CPU interface.");
      } else {
        // Read message from CPU
        mbedtls_printf("Receiving message on CPU interface.");
        len = read_msg(CPU_INTF, &hdr, cpu_buf, sizeof(cpu_buf), 1);
        mbedtls_printf("Received message from CPU.");

        if (hdr.tgt_id == SCEWL_BRDCST_ID) {
          scum_send(&scum_ctx, len);
        } else if (hdr.tgt_id == SCEWL_SSS_ID) {
          mbedtls_printf("CPU requested to talk to SSS. Rekeying to provision keys.");
          dtls_rekey_to_default(&dtls_state, true, false);
          dtls_send_message_to_sss(&dtls_state, cpu_buf, len);
        } else if (hdr.tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(cpu_buf, len);
        } else {
          dtls_send_message(&dtls_state, hdr.tgt_id, cpu_buf, len);
        }
      }
    }

    // handle incoming radio message
    if (intf_avail(RAD_INTF)) {
      // Read message from antenna
      read_hdr(RAD_INTF, &hdr, 1);
      if (hdr.src_id == SCEWL_ID) { // ignore our own outgoing messages
        read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
      } else {
        if (hdr.tgt_id == SCEWL_BRDCST_ID) {
          // Receive broadcast message
          if ((dtls_state.status != IDLE) && (!dtls_backed_up)) {
            // Backup unicast
            backup_buf(cpu_buf, DTLS);
            dtls_backed_up = 1;
          }
          if (scum_backed_up) {
            // Restore broadcast
            restore_buf(cpu_buf, SCUM);
            scum_backed_up = 0;
          }
          len = read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
          scum_handle(&scum_ctx, hdr.src_id, scewl_buf, len);
        } else if (hdr.tgt_id == SCEWL_ID) {
          // Receive unicast message
          if (hdr.src_id == SCEWL_FAA_ID) {
            if ((dtls_state.status != IDLE) && (!dtls_backed_up)) {
              // Backup unicast
              backup_buf(cpu_buf, DTLS);
              dtls_backed_up = 1;
            } else if ((scum_ctx.data_session.status == S_RECV) && (!scum_backed_up)) {
              // Backup broadcast
              backup_buf(cpu_buf, SCUM);
              scum_backed_up = 1;
            }
            len = read_body(RAD_INTF, &hdr, cpu_buf, sizeof(cpu_buf), 1);
            handle_faa_recv(cpu_buf, len);
          } else {
            if ((scum_ctx.data_session.status == S_RECV) && (!scum_backed_up)) {
              // Backup broadcast
              backup_buf(cpu_buf, SCUM);
              scum_backed_up = 1;
            }
            if (dtls_backed_up) {
              // Restore unicast
              restore_buf(cpu_buf, DTLS);
              dtls_backed_up = 0;
            }
            len = read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
            dtls_handle_packet(&dtls_state, hdr.src_id, scewl_buf, len);
          }
        } else { // ignore messages for other devices
          read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
        }
      }
    }

    // handle incoming message from SSS
    if (intf_avail(SSS_INTF)) {
      if (dtls_state.status != TALKING_TO_SSS) {
        mbedtls_printf("Discarding unsolicited packet on SSS interface.");
        read_msg(SSS_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
      } else {
        // Read message from wire
        mbedtls_printf("Receiving packet on SSS interface.");
        len = read_msg(SSS_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
        if (hdr.src_id == SCEWL_SSS_ID && hdr.tgt_id == SCEWL_ID) {
          mbedtls_printf("Received packet from SSS.");
          dtls_handle_packet(&dtls_state, hdr.src_id, scewl_buf, len);
        } else {
          mbedtls_printf("Received bogon on SSS interface.");
        }
      }
    }
  }
}
