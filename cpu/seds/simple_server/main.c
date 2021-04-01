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

#define DLEN 0x4000

// DEVICE_ID and INSEC_ID need to be defined at compile

#define STR_(X) #X
#define STR(X) STR_(X)
#define TAG STR(SCEWL_ID) ":"
#define FMT_MSG(M) TAG M ";"

#define send_str(M) scewl_send(SCEWL_FAA_ID, strlen(M), M)

int main(void) {
  scewl_id_t src_id, tgt_id;
  char data[DLEN];
  int len;

  // initialize interfaces and scewl
  scewl_init();

  // register
  if (scewl_register() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
    return 1;
  }

  send_str(FMT_MSG("REG"));

  // loop until quit received
  len = scewl_recv(data, &src_id, &tgt_id, DLEN, 0);
  do {
    // receive packet
    if (len >= 0 && len != SCEWL_NO_MSG) {
      send_str(data);
    }
    usleep(10000);
    len = scewl_recv(data, &src_id, &tgt_id, DLEN, 0);
  } while (data[0] != 'q' || data[1] != 'u' || data[2] != 'i' || data[3] != 't');

  send_str(FMT_MSG("DONE"));
  
  // degister
  if (scewl_deregister() != SCEWL_OK) {
    send_str(FMT_MSG("BAD"));
  }
  sleep(30);
}