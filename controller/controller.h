/*
 * 2021 Collegiate eCTF
 * SCEWL Bus Controller header
 * Ted Clifford
 *
 * (c) 2021 The MITRE Corporation
 *
 * This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 */

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "interface.h"
#include "lm3s/lm3s_cmsis.h"
#include "dtls.h"

#include <stdint.h>
#include <string.h>

#define SCEWL_MAX_DATA_SZ 0x4000

// type of a SCEWL ID
typedef uint16_t scewl_id_t;

// SCEWL_ID defined at compile
#ifndef SCEWL_ID
#warning SCEWL_ID not defined, using bad default of 0
#define SCEWL_ID 0
#endif


// Flash interaction definitions
#define FLASH_FMA_OFFSET_M ((uint32_t)0x0003FFFF)
#define FLASH_FMC_WRKEY    ((uint32_t)0xA4420000)
#define FLASH_FMC_ERASE_M  ((uint32_t)0x00000002)
#define FLASH_FMC_WRITE_M  ((uint32_t)0x00000001)

#define PAGE_SIZE         (1024)
#define FLASH_END         ((uint32_t)0x00040000)
#define WORDS_PER_BUF     (((SCEWL_MAX_DATA_SZ-1)/4)+1)
#define PAGES_PER_BUF     (((SCEWL_MAX_DATA_SZ-1)/PAGE_SIZE)+1) // Round up
#define DTLS_BACKUP_START (FLASH_END-(PAGES_PER_BUF*1))
#define SCUM_BACKUP_START (FLASH_END-(PAGES_PER_BUF*2))

enum proto_type {
  DTLS,
  SCUM
};


// SCEWL bus channel header
// NOTE: This is the required format to comply with Section 4.6 of the rules
typedef struct scewl_hdr_t {
  uint8_t magicS;  // all messages must start with the magic code "SC"
  uint8_t magicC;
  scewl_id_t tgt_id;
  scewl_id_t src_id;
  uint16_t len;
  /* data follows */
} scewl_hdr_t;

// registration message
typedef struct scewl_sss_msg_t {
  scewl_id_t dev_id;
  uint16_t   op;
  uint16_t ca_len;
  uint16_t crt_len;
  uint16_t key_len;
  uint16_t sync_key_len;
  uint16_t sync_salt_len;
  uint16_t data_key_len;
  uint16_t data_salt_len;
  uint16_t sync_len;
  uint16_t entropy_len;
  /* data follows */
} scewl_sss_msg_t;

// SCEWL status codes
enum scewl_status { SCEWL_ERR = -2, SCEWL_NO_MSG = -1, SCEWL_OK, SCEWL_ALREADY };

// registration/deregistration options
enum scewl_sss_op_t { SCEWL_SSS_BAD_REQUEST = -1, SCEWL_SSS_REG, SCEWL_SSS_DEREG };

// reserved SCEWL IDs
enum scewl_ids { SCEWL_BRDCST_ID, SCEWL_SSS_ID, SCEWL_FAA_ID };

/*
 * read_hdr
 *
 * Gets a message header in the SCEWL pkt format from an interface
 *
 * Args:
 *   intf - pointer to the physical interface device
 *   hdr - pointer to header
 *   blocking - whether to wait for a message or not
 */
int read_hdr(intf_t *intf, scewl_hdr_t *hdr, int blocking);

/*
 * read_body
 *
 * Gets a message body in the SCEWL pkt format from an interface
 *
 * Args:
 *   intf - pointer to the physical interface device
 *   hdr - pointer to header
 *   buf - pointer to the message buffer
 *   n - maximum characters to be read into buf
 *   blocking - whether to wait for a message or not
 */
int read_body(intf_t *intf, scewl_hdr_t *hdr, char *buf, size_t n, int blocking);

/*
 * read_msg
 *
 * Gets a message in the SCEWL pkt format from an interface
 *
 * Args:
 *   intf - pointer to the physical interface device
 *   hdr - pointer to header
 *   buf - pointer to the message buffer
 *   n - maximum characters to be read into buf
 *   blocking - whether to wait for a message or not
 */
int read_msg(intf_t *intf, scewl_hdr_t *hdr, char *buf, size_t n, int blocking);

/*
 * send_msg
 * 
 * Sends a message in the SCEWL pkt format to an interface
 * 
 * Args:
 *   intf - pointer to the physical interface device
 *   src_id - the id of the sending device
 *   tgt_id - the id of the receiving device
 *   len - the length of message
 *   data - pointer to the message
 */
int send_msg(intf_t *intf, scewl_id_t src_id, scewl_id_t tgt_id, uint16_t len, const char *data);

/*
 * handle_sss_recv
 * 
 * Handles a message received from the SSS
 */
void handle_sss_recv(struct dtls_state *dtls_state, const char* data, uint16_t len);

/*
 * handle_scewl_recv
 * 
 * Interprets a SCEWL tranmission from another SED and sends the message to the CPU
 */
int handle_scewl_recv(const char* data, scewl_id_t src_id, uint16_t len);

/*
 * handle_brdcst_recv
 * 
 * Interprets a broadcast message from another SED and passes it to the CPU
 */
int handle_brdcst_recv(const char* data, scewl_id_t src_id, uint16_t len);

/*
 * handle_brdcst_send
 * 
 * Broadcasts a message from the CPU to SEDS over the antenna
 */
int handle_brdcst_send(const char *data, uint16_t len);

/*
 * handle_faa_recv
 * 
 * Receives an FAA message from the antenna and passes it to the CPU
 */
int handle_faa_recv(const char* data, uint16_t len);

/*
 * handle_faa_send
 * 
 * Sends an FAA message from the CPU to the antenna
 */
int handle_faa_send(const char* data, uint16_t len);

#endif

