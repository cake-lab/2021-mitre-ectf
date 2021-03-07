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

#include <stdint.h>
#include "dtls.h"

/*
 * handle_sss_recv
 * 
 * Handles a message received from the SSS
 */
void handle_sss_recv(struct dtls_state *dtls_state, const char* data, uint16_t len);

/*
 * Emulated exit function
 * Kills Qemu process by executing non-existent memory
 */
void exit(int status);

#endif

