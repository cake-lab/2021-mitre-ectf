/*
 * 2020 Summer eCTF
 * Example echo server
 * Ben Janis
 *
 * (c) 2020 The MITRE Corporation
 * For internal use only
 */

#include "scewl_bus_driver/scewl_bus.h"
#include <string.h>
#include <unistd.h>

// DEVICE_ID and INSEC_ID and RECVR_ID need to be defined at compile

#define STR_(X) #X
#define STR(X) STR_(X)
#define TAG STR(SCEWL_ID) ":"
#define FMT_MSG(M) TAG M ";"

#define DLEN 0x100

#define send_str(M) scewl_send(SCEWL_FAA_ID, strlen(M), M)

void strncpy_(char *dst, char *src, int n) {
  for (int i = 0; i < n - 1 && src[i]; i++) {
    dst[i] = src[i];
    dst[i + 1] = 0;
  }
}


int main(void) {
  char msg[DLEN];
  int len;

  strncpy_(msg, FMT_MSG("OK TEST"), DLEN);

  // initialize interfaces and scewl
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
    return 1;
  }

  send_str(FMT_MSG("REG"));

  // get length of message
  for (len = 0; msg[len]; len++);
  scewl_send(RECVR_ID, len, msg);

  send_str(FMT_MSG("DONE"));

  // degister
  if (scewl_deregister() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
  }
  sleep(30);
}

