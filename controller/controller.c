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
#include "dtls.h"

// Cannot include printf.h because it contains preprocessor defines that cause problems
// These functions are defined in printf.c
int snprintf_(char *buffer, size_t count, const char *format, ...);
int vsnprintf_(char *buffer, size_t count, const char *format, va_list va);

// this will run if EXAMPLE_AES is defined in the Makefile (see line 54)
#ifdef EXAMPLE_AES
#include "aes.h"

char int2char(uint8_t i) {
  char *hex = "0123456789abcdef";
  return hex[i & 0xf];
}
#endif

#define send_str(M) send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, strlen(M), M)
#define BLOCK_SIZE 16
#define MAX_PRINTF_LENGTH 1000
#define DEBUG_LEVEL 0


int read_msg(intf_t *intf, char *data, scewl_id_t *src_id, scewl_id_t *tgt_id,
             size_t n, int blocking) {
  scewl_hdr_t hdr;
  int read, max;

  do {
    // clear buffer and header
    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, n);

    // find header start
    do {
      hdr.magicC = 0;

      if (intf_read(intf, (char *)&hdr.magicS, 1, blocking) == INTF_NO_DATA) {
        return SCEWL_NO_MSG;
      }

      // check for SC
      if (hdr.magicS == 'S') {
        do {
          if (intf_read(intf, (char *)&hdr.magicC, 1, blocking) == INTF_NO_DATA) {
            return SCEWL_NO_MSG;
          }
        } while (hdr.magicC == 'S'); // in case of multiple 'S's in a row
      }
    } while (hdr.magicS != 'S' && hdr.magicC != 'C');

    // read rest of header
    read = intf_read(intf, (char *)&hdr + 2, sizeof(scewl_hdr_t) - 2, blocking);
    if(read == INTF_NO_DATA) {
      return SCEWL_NO_MSG;
    }

    // unpack header
    *src_id = hdr.src_id;
    *tgt_id = hdr.tgt_id;

    // read body
    max = hdr.len < n ? hdr.len : n;
    read = intf_read(intf, data, max, blocking);

    // throw away rest of message if too long
    for (int i = 0; hdr.len > max && i < hdr.len - max; i++) {
      intf_readb(intf, 0);
    }

    // report if not blocking and full message not received
    if(read == INTF_NO_DATA || read < max) {
      return SCEWL_NO_MSG;
    }

  } while (intf != CPU_INTF && intf != SSS_INTF &&                       // always valid if from CPU or SSS
           ((hdr.tgt_id == SCEWL_BRDCST_ID && hdr.src_id == SCEWL_ID) || // ignore own broadcast
            (hdr.tgt_id != SCEWL_BRDCST_ID && hdr.tgt_id != SCEWL_ID))); // ignore direct message to other device

  return max;
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


int handle_scewl_recv(const char* data, scewl_id_t src_id, uint16_t len) {
  return send_msg(CPU_INTF, src_id, SCEWL_ID, len, data);
}


int handle_scewl_send(const char* data, scewl_id_t tgt_id, uint16_t len) {
  return send_msg(RAD_INTF, SCEWL_ID, tgt_id, len, data);
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


int handle_registration(char* msg) {
  scewl_sss_msg_t *sss_msg = (scewl_sss_msg_t *)msg;
  if (sss_msg->op == SCEWL_SSS_REG) {
    return sss_register();
  }
  else if (sss_msg->op == SCEWL_SSS_DEREG) {
    return sss_deregister();
  }

  // bad op
  return 0;
}


int sss_register() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_REG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be REG on success
  return msg.op == SCEWL_SSS_REG;
}


int sss_deregister() {
  scewl_sss_msg_t msg;
  scewl_id_t src_id, tgt_id;
  int status, len;

  // fill registration message
  msg.dev_id = SCEWL_ID;
  msg.op = SCEWL_SSS_DEREG;
  
  // send registration
  status = send_msg(SSS_INTF, SCEWL_ID, SCEWL_SSS_ID, sizeof(msg), (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // receive response
  len = read_msg(SSS_INTF, (char *)&msg, &src_id, &tgt_id, sizeof(scewl_sss_msg_t), 1);

  // notify CPU of response
  status = send_msg(CPU_INTF, src_id, tgt_id, len, (char *)&msg);
  if (status == SCEWL_ERR) {
    return 0;
  }

  // op should be DEREG on success
  return msg.op == SCEWL_SSS_DEREG;
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
  char message[MAX_PRINTF_LENGTH];

  va_start(args, format);
  int length = vsnprintf_(message, MAX_PRINTF_LENGTH, format, args);
  va_end(args);
  if (length > MAX_PRINTF_LENGTH) {
    length = MAX_PRINTF_LENGTH;
  }
  handle_faa_send(message, length);
  return length;
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

static void main_loop(void) {
  int registered = 0, len;
  scewl_hdr_t hdr;
  uint16_t src_id, tgt_id;
  // message buffer
  char buf[SCEWL_MAX_DATA_SZ];

  // serve forever
  while (1) {
    // register with SSS
    read_msg(CPU_INTF, buf, &hdr.src_id, &hdr.tgt_id, sizeof(buf), 1);

    if (hdr.tgt_id == SCEWL_SSS_ID) {
      registered = handle_registration(buf);
    }

    // server while registered
    while (registered) {
      memset(&hdr, 0, sizeof(hdr));

      // handle outgoing message from CPU
      if (intf_avail(CPU_INTF)) {
        // Read message from CPU
        len = read_msg(CPU_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_send(buf, len);
        } else if (tgt_id == SCEWL_SSS_ID) {
          registered = handle_registration(buf);
        } else if (tgt_id == SCEWL_FAA_ID) {
          handle_faa_send(buf, len);
        } else {
          handle_scewl_send(buf, tgt_id, len);
        }

        continue;
      }

      // handle incoming radio message
      if (intf_avail(RAD_INTF)) {
        // Read message from antenna
        len = read_msg(RAD_INTF, buf, &src_id, &tgt_id, sizeof(buf), 1);

        if (tgt_id == SCEWL_BRDCST_ID) {
          handle_brdcst_recv(buf, src_id, len);
        } else if (src_id == SCEWL_FAA_ID) {
          handle_faa_recv(buf, len);
        } else {
          handle_scewl_recv(buf, src_id, len);
        }
      }
    }
  }
}

int main() {
  struct dtls_state dtls_state;
  // heap memory for mbedtls
  unsigned char memory_buf[10000];

  // heap memory for mbedtls
  mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));
  // replacements for stdlib functions for mbedtls
  mbedtls_platform_set_exit(exit);
  mbedtls_platform_set_printf(printf);
  mbedtls_platform_set_snprintf(snprintf_);
  mbedtls_platform_set_vsnprintf(vsnprintf_);
#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
  mbedtls_printf("Hello, world! This is from main.");
  dtls_setup(&dtls_state);

  // initialize interfaces
  intf_init(CPU_INTF);
  intf_init(SSS_INTF);
  intf_init(RAD_INTF);

#ifdef EXAMPLE_AES
  // example encryption using tiny-AES-c
  struct AES_ctx ctx;
  uint8_t key[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  uint8_t plaintext[16] = "0123456789abcdef";

  // initialize context
  AES_init_ctx(&ctx, key);

  // encrypt buffer (encryption happens in place)
  AES_ECB_encrypt(&ctx, plaintext);
  send_str("Example encrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);

  // decrypt buffer (decryption happens in place)
  AES_ECB_decrypt(&ctx, plaintext);
  send_str("Example decrypted message:");
  send_msg(RAD_INTF, SCEWL_ID, SCEWL_FAA_ID, BLOCK_SIZE, (char *)plaintext);
  // end example
#endif

  main_loop();
}
