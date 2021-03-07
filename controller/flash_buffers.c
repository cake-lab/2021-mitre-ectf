/*
 * Author: Jacob T. Grycel
 * Description: 
 */

#include "controller.h"
#include "flash_buffers.h"
#include "mbedtls/platform.h"


/* References to dedicate Flash buffer region */
extern unsigned long _flash_bufs_start;
extern unsigned long _faa_buf_start;
extern unsigned long _dtls_buf_start;
extern unsigned long _scum_buf_start;


/* System Flash Buffers */
struct flash_buf DTLS_FBUF = {.start_addr=(uint32_t)&_dtls_buf_start, .partial_data={0,0,0,0}, .partial_count=0, .write_pos=0};
struct flash_buf SCUM_FBUF = {.start_addr=(uint32_t)&_scum_buf_start, .partial_data={0,0,0,0}, .partial_count=0, .write_pos=0};
struct flash_buf FAA_FBUF = {.start_addr=(uint32_t)&_faa_buf_start, .partial_data={0,0,0,0}, .partial_count=0, .write_pos=0};


static void flash_erase_buf(struct flash_buf *dst_buf) {
  // Erase all pages
  for (uint32_t i = 0; i < PAGES_PER_BUF; i++) {
    FLASH_CTRL->FMA &= ~(FLASH_FMA_OFFSET_M); // Clear address field
    FLASH_CTRL->FMA |= (dst_buf->start_addr + (i*PAGE_SIZE)); // Write address field
    FLASH_CTRL->FMC |= (FLASH_FMC_WRKEY | FLASH_FMC_ERASE_M); // Start erase
    while (FLASH_CTRL->FMC & FLASH_FMC_ERASE_M); // Wait until erase bit is 0
  }

  dst_buf->partial_count = 0;
  dst_buf->write_pos = 0;
}

static inline void flash_write_word(struct flash_buf *dst_buf, char *src_buf) {
  // Program one 32-bit word into Flash address
  FLASH_CTRL->FMA &= ~FLASH_FMA_OFFSET_M; // Clear address field
  FLASH_CTRL->FMA |= (dst_buf->start_addr + dst_buf->write_pos); // Write address field
  FLASH_CTRL->FMD = *((uint32_t *)(src_buf)); // Write 32 bits
  FLASH_CTRL->FMC |= (FLASH_FMC_WRKEY | FLASH_FMC_WRITE_M); // Start write
  while (FLASH_CTRL->FMC & FLASH_FMC_WRITE_M); // Wait until write bit is 0

  dst_buf->write_pos += 4;
}

void flash_commit_buf(struct flash_buf *dst_buf) {
  if (dst_buf->partial_count != 0) {
    while (dst_buf->partial_count < 4) {
      dst_buf->partial_data[dst_buf->partial_count++] = 0;
    }
    dst_buf->partial_count = 0;
    flash_write_word(dst_buf, dst_buf->partial_data);
  }
}

void flash_write_buf(struct flash_buf *dst_buf, char *src_buf, size_t len, char new) {
  size_t write_len;
  size_t read_pos;

  // Erase buffer if writing from beginning
  if (new) {
    flash_erase_buf(dst_buf);
  }

  // Limit write size
  if (dst_buf->write_pos + dst_buf->partial_count + len > SCEWL_MAX_DATA_SZ) {
    write_len = SCEWL_MAX_DATA_SZ - dst_buf->write_pos - dst_buf->partial_count;
  } else {
    write_len = len;
  }

  read_pos = 0;

  // Handle previous partial write
  // Add minimum of [bytes left in word] and [bytes in src_buf] 
  if (dst_buf->partial_count != 0) {
    while ((dst_buf->partial_count < 4) && (read_pos < len)) {
      dst_buf->partial_data[dst_buf->partial_count++] = src_buf[read_pos++];
    }

    if (dst_buf->partial_count == 4) {
      flash_write_word(dst_buf, dst_buf->partial_data);
      dst_buf->partial_count = 0;
    }
  }

  // Loop through each word in the source buffer and write
  while (read_pos+4 <= write_len) {
    flash_write_word(dst_buf, src_buf+read_pos);
    read_pos += 4;
  }

  // Store remaining bytes for future write
  while (read_pos < write_len) {
    dst_buf->partial_data[dst_buf->partial_count++] = src_buf[read_pos++];
  }
}

char* flash_get_buf(struct flash_buf *src_buf) {
  return (char *)(src_buf->start_addr);
}