/*
 * 2021 Collegiate eCTF
 * Test broadcast SED
 * Ben Janis
 *
 * (c) 2021 The MITRE Corporation
 */

#include "scewl_bus_driver/scewl_bus.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// DEVICE_ID and INSEC_ID need to be defined at compile

#define STR_(X) #X
#define STR(X) STR_(X)
#define TAG STR(SCEWL_ID) ":"
#define FMT_MSG(M) TAG M ";"

#define LEN 256
#define SHIFT 3

#define send_str(M) scewl_send(SCEWL_FAA_ID, strlen(M), M)

int main(void) {
  char idata[LEN], odata[LEN], strbuf[1000];
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
  fprintf(log, "%d: registered\n", SCEWL_ID);
  // send_str(FMT_MSG("REG"));

  // wait for start message
  scewl_recv(idata, &src_id, &tgt_id, LEN, 1);

  while (1) {
    scewl_brdcst(LEN, odata);
    fprintf(log, "%d: Sent broadcast\n", SCEWL_ID);
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
            sprintf(strbuf, "%d: Bad message from src_id: %d\n", SCEWL_ID, src_id);
            fprintf(log, "%s", strbuf);
            // send_str(strbuf);
          } else {
             sprintf(strbuf, "%d: GOOD message from src_id: %d\n", SCEWL_ID, src_id);
             fprintf(log, "%s", strbuf);
            // send_str(strbuf);
          }
        }
      }
    }
  }
  done:

  fprintf(log, "%d: Finished\n", SCEWL_ID);
  // send_str(FMT_MSG("DONE"));

  // degister
  if (scewl_deregister() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
  }
  sleep(30);
}

