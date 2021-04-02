/*
 * Description: SCEWL sending and receiving functions
 */

#include "scewl.h"
#include "mbedtls/platform.h"


/*
 * Read Message Header
 */
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
  if (read == INTF_NO_DATA) {
    return SCEWL_NO_MSG;
  }

  return SCEWL_OK;
}


/*
 * Read Message Body into Buffer
 */
int read_body(intf_t *intf, scewl_hdr_t *hdr, char *data, size_t n, int blocking) {
  int read, max;

  // clear buffer
  memset(data, 0, n);

  if (intf == SSS_INTF) {
    mbedtls_printf("Packet has payload length %hu.", hdr->len);
  }

  // Limit bytes read to either requested length or header length (smallest)
  max = hdr->len < n ? hdr->len : n;
  // Read body
  read = intf_read(intf, data, max, blocking);

  // Throw away rest of message if too long
  for (int i = 0; hdr->len > max && i < hdr->len - max; i++) {
    intf_readb(intf, blocking);
  }

  // Report if not blocking and full message not received
  if (read == INTF_NO_DATA || read < max) {
    return SCEWL_NO_MSG;
  }

  return max;
}


/*
 * Read Full Message into Buffer
 */
int read_msg(intf_t *intf, scewl_hdr_t *hdr, char *data, size_t n, int blocking) {
  if (read_hdr(intf, hdr, blocking) == SCEWL_NO_MSG) {
    return SCEWL_NO_MSG;
  }
  return read_body(intf, hdr, data, n, blocking);
}


/*
 * Read Message Body into Flash Buffer
 */
int read_body_flash(intf_t *intf, scewl_hdr_t *hdr, struct flash_buf *dst_buf, size_t n, int blocking) {
  int read, max, req_len, first = 1;
  char temp_buf[4];

  if (intf == SSS_INTF) {
    mbedtls_printf("Packet has payload length %hu.", hdr->len);
  }

  // Limit bytes read to either requested length or header length (smallest)
  max = hdr->len < n ? hdr->len : n;

  // Read body
  for (int i = 0; i < max; i += 4) {
    // Clear buffer
    memset(temp_buf, 0, 4);

    // Read 4 bytes or less
    req_len = (max - i >= 4) ? 4 : (max - i);
    read = intf_read(intf, temp_buf, req_len, blocking);

    // Report if not blocking and full message not received
    if (read == INTF_NO_DATA || read < req_len) {
      return SCEWL_NO_MSG;
    }

    // Write to buffer
    flash_write_buf(dst_buf, temp_buf, req_len, first);
    first = 0;
  };

  // Throw away rest of message if too long
  for (int i = 0; hdr->len > max && i < hdr->len - max; i++) {
    intf_readb(intf, blocking);
  }

  // Commit leftovers to flash
  flash_commit_buf(dst_buf);

  return max;
}


/*
 * Read Full Message into Flash Buffer
 */
int read_msg_flash(intf_t *intf, scewl_hdr_t *hdr, struct flash_buf *dst_buf, size_t n, int blocking) {
  if (read_hdr(intf, hdr, blocking) == SCEWL_NO_MSG) {
    return SCEWL_NO_MSG;
  }
  return read_body_flash(intf, hdr, dst_buf, n, blocking);
}


/*
 * Send Message from Buffer
 */
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