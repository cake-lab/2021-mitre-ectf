/*
 * 2021 Collegiate eCTF
 * Test broadcast SED
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 */

#include "scewl_bus_driver/scewl_bus.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// DEVICE_ID and INSEC_ID need to be defined at compile

#define STR_(X) #X
#define STR(X) STR_(X)
#define TAG STR(SCEWL_ID) ":"
#define FMT_MSG(M) TAG M ";"

#define send_str(M) scewl_send(SCEWL_FAA_ID, strlen(M), M)

int main(void) {
  char idata[LEN], odata[LEN];
  char mask = 1 << SHIFT;
  scewl_id_t src_id, tgt_id;
  int len = -1, ok;

  FILE *log = stderr;

  // set up outgoing message
  for (int i = 0; i < LEN; i++) {
    odata[i] = i & 0xff;
  }
  odata[0] = mask;

  // initialize scewl
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
    return 1;
  }
  send_str(FMT_MSG("REG"));

  // wait for start message
  fprintf(log, "%d: Waiting for start\n", SCEWL_ID);
  scewl_recv(idata, &src_id, &tgt_id, LEN, 1);

  while (1) {
    scewl_brdcst(LEN, odata);
    sleep(30);

    for (int n = 0; n < 8; n++) {
      // receive new message
      len = scewl_recv(idata, &src_id, &tgt_id, LEN, 0);

      if (!memcmp(idata, "quit", 4)) {
        goto done;
      }

      if (len != SCEWL_NO_MSG) {
        ok = 1;
        // check for matching message
        if (len >= 0 && mask != 0xff) {
          for (int i = 1; i < LEN; i++) {
            if (idata[i] != (i & 0xff)) {
              ok = 0;
              break;
            }
          }
          if (len != LEN || !ok) {
            send_str(FMT_MSG("BAD"));
            fprintf(log, "%s", FMT_MSG("BAD - length or bytes not okay"));
          }
          mask |= idata[0];
          fprintf(log, "%d: Got broadcast from %d\n", SCEWL_ID, src_id);
          if (mask == 0xff) {
            fprintf(log, "%d: Got all broadcasts\n", SCEWL_ID);
            send_str(FMT_MSG("OK"));
          }
        }
      }
    }
  }
done:

  send_str(FMT_MSG("DONE"));

  // degister
  if (scewl_deregister() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
  }
  sleep(30);
}

