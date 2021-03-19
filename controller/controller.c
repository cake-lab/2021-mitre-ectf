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
#include "scewl.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "broadcast.h"
#include "dtls.h"
#include "masked_aes.h"
#include "flash_buffers.h"
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
 * Handle registration / deregistratio
 * Re-keys communication protocols and re-configures RNG modules
 */
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
          mbedtls_printf("Registered.");

          // Setup runtime RNG state -- happens by default in SCUM
          rng_setup_runtime_pool((unsigned char *)entropy, msg->entropy_len);
          dtls_setup_rng(dtls_state);
          if (Masked_AES_RNG_Setup(aes_hmac_drbg_ref) != 0) {
            mbedtls_printf("Error setting up masked AES rng. Entering death loop.");
            exit(1);
          }

          // Configure SCUM
          scum_setup(scum_ctx_ref,
                   (char *)sync_key, (char *)sync_salt,
                   (char *)data_key, (char *)data_salt,
                   &SCUM_FBUF, *first_sed);

          if (scum_ctx_ref->status == S_UNSYNC) {
            scum_sync(scum_ctx_ref);
            mbedtls_printf("Sent SCUM sync request...");
          }
          break;
        case SCEWL_SSS_DEREG:
          dtls_rekey_to_default(dtls_state, true, false);
          // Setup initial RNG state
          rng_clear_runtime_pool();
          dtls_setup_rng(dtls_state);
          if (Masked_AES_RNG_Setup(aes_hmac_drbg_ref) != 0) {
            mbedtls_printf("Error setting up masked AES rng. Entering death loop.");
            exit(1);
          }
          // Clear SCUM
          scum_init(scum_ctx_ref);
          mbedtls_printf("Deregistered.");
          break;
        default:
          mbedtls_printf("Received response from SSS with invalid status.");
      }
      if (!illegal_len) {
        // forward message to CPU -- clear data except for device ID and op
        const uint16_t cpu_required_len = sizeof(msg->dev_id) + sizeof(msg->op);
        // memset((unsigned char *)data+cpu_required_len, 0, len - cpu_required_len);
        send_msg(CPU_INTF, SCEWL_SSS_ID, SCEWL_ID, cpu_required_len, data);
        return;
      }
    }
  }
  mbedtls_printf("Received invalid response from SSS.");
}

/*
 * Main controller loop
 */
int main() {
  
  // Heap memory for mbedtls
  unsigned char memory_buf[40000];
  // Buffer for incoming SCEWL packets
  char scewl_buf[SCEWL_MTU];
  // Scewl message info
  scewl_hdr_t hdr;
  int len;
  // Communication protocols
  struct scum_ctx scum_ctx;
  struct dtls_state dtls_state;
  // RNG for masked AES
  mbedtls_hmac_drbg_context aes_hmac_drbg;

  // Set global refs
  aes_hmac_drbg_ref = &aes_hmac_drbg;
  scum_ctx_ref = &scum_ctx;

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
  if (Masked_AES_RNG_Setup(&aes_hmac_drbg) != 0) {
    mbedtls_printf("Error setting up masked AES rng. Entering death loop.");
    exit(1);
  }

  // Setup / initialize protocols
  dtls_setup(&dtls_state, &DTLS_FBUF);
  scum_init(&scum_ctx);

  // serve forever
  while (1) {

    // Handle timer events
    if (fin_timer_event) {
      fin_timer_event = 0;
      dtls_check_timers(&dtls_state);
    }
    if (sync_timer_event) {
      sync_timer_event = 0;
      scum_timeout(&scum_ctx);
    }

    // Handle outgoing message from CPU
    if (intf_avail(CPU_INTF)) {
      if (dtls_state.status != IDLE || scum_ctx.status == S_WAIT_SYNC || scum_ctx.status == S_RECV) {
        mbedtls_printf("There is a message waiting on the CPU interface.");
      } else {

        // Read header from CPU
        mbedtls_printf("Receiving message on CPU interface.");
        read_hdr(CPU_INTF, &hdr, 1);

        if (hdr.tgt_id == SCEWL_BRDCST_ID) { // Send Broadcast

          len = read_body_flash(CPU_INTF, &hdr, &SCUM_FBUF, SCEWL_MAX_DATA_SZ, 1);
          scum_send(&scum_ctx, flash_get_buf(&SCUM_FBUF), len);

        } else if (hdr.tgt_id == SCEWL_SSS_ID) { // Send to SSS

          len = read_body_flash(CPU_INTF, &hdr, &DTLS_FBUF, SCEWL_MAX_DATA_SZ, 1);
          mbedtls_printf("CPU requested to talk to SSS. Rekeying to provision keys.");
          dtls_rekey_to_default(&dtls_state, true, false);
          dtls_send_message_to_sss(&dtls_state, flash_get_buf(&DTLS_FBUF), len);

        } else if (hdr.tgt_id == SCEWL_FAA_ID) { // Send to FAA

          len = read_body_flash(CPU_INTF, &hdr, &FAA_FBUF, SCEWL_MAX_DATA_SZ, 1);
          handle_faa_send(flash_get_buf(&FAA_FBUF), len);

        } else { // Send Unicast

          len = read_body_flash(CPU_INTF, &hdr, &DTLS_FBUF, SCEWL_MAX_DATA_SZ, 1);
          dtls_send_message(&dtls_state, hdr.tgt_id, flash_get_buf(&DTLS_FBUF), len);

        }
      }
    }

    // handle incoming radio message
    if (intf_avail(RAD_INTF)) {
      // Read header from antenna
      read_hdr(RAD_INTF, &hdr, 1);
      if (hdr.src_id == SCEWL_ID) { // Ignore our own outgoing messages
        read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
      } else {

        if ((hdr.src_id == SCEWL_FAA_ID) && ((hdr.tgt_id == SCEWL_ID) || (hdr.tgt_id == SCEWL_BRDCST_ID))) { // Handle FAA

          len = read_body_flash(RAD_INTF, &hdr, &FAA_FBUF, SCEWL_MAX_DATA_SZ, 1);
          handle_faa_recv(flash_get_buf(&FAA_FBUF), len);

        } else if (hdr.tgt_id == SCEWL_BRDCST_ID) { // Handle Broadcast

          len = read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
          scum_handle(&scum_ctx, hdr.src_id, scewl_buf, len);

        } else if (hdr.tgt_id == SCEWL_ID && dtls_state.status != TALKING_TO_SSS) { // Handle Unicast

          len = read_body(RAD_INTF, &hdr, scewl_buf, sizeof(scewl_buf), 1);
          dtls_handle_packet(&dtls_state, hdr.src_id, scewl_buf, len);

        } else { // Ignore messages for other devices

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
