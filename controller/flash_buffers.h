/*
 * Author: Jacob T. Grycel
 * Description: Functionality for using Flash-based buffers to store maximum
 *              SCEWL length messages. Flash buffer regions are set up in
 *              `lm3s/controller.ld`
 */

#ifndef FLASH_BUFFERS_H
#define FLASH_BUFFERS_H

#include <stdint.h>

struct flash_buf {
  uint32_t start_addr;
  char partial_data[4];
  uint8_t partial_count;
  uint16_t write_pos;
};

#include "scewl.h"

// Flash interaction definitions
#define FLASH_FMA_OFFSET_M ((uint32_t)0x0003FFFF)
#define FLASH_FMC_WRKEY    ((uint32_t)0xA4420000)
#define FLASH_FMC_ERASE_M  ((uint32_t)0x00000002)
#define FLASH_FMC_WRITE_M  ((uint32_t)0x00000001)

#define PAGE_SIZE         (1024)
#define FLASH_END         ((uint32_t)0x00040000)
#define WORDS_PER_BUF     (((SCEWL_MAX_DATA_SZ-1)/4)+1)
#define PAGES_PER_BUF     (((SCEWL_MAX_DATA_SZ-1)/PAGE_SIZE)+1) // Round up


extern struct flash_buf DTLS_FBUF;
extern struct flash_buf SCUM_FBUF;
extern struct flash_buf FAA_FBUF;


void flash_commit_buf(struct flash_buf *dst_buf);
void flash_write_buf(struct flash_buf *dst_buf, char *src_buf, size_t len, char new);
char *flash_get_buf(struct flash_buf *src_buf);

#endif