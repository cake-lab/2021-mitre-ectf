/*
 * Author: Ryan LaPointe <ryan@ryanlapointe.org>
 */

#ifndef DTLS_H
#define DTLS_H

#include <stdbool.h>

#include "controller.h"

#include "mbedtls/md.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

enum dtls_status {
	IDLE,
	SENDING_MESSAGE,
	RECEIVING_MESSAGE,
	FATAL_ERROR
};

enum dtls_session_status {
	HANDSHAKE,
	READ,
	WRITE,
	DONE
};

struct dtls_timers {
  uint32_t int_ms;
  uint32_t fin_ms;
  uint8_t  int_expired;
  uint8_t  fin_expired;
};

struct dtls_server_state {
	scewl_id_t client_scewl_id;
	enum dtls_session_status status;
	struct dtls_timers timers;

	// encrypted data received over SCEWL
	bool data_available;
	char *data;
	size_t data_len;

	// decrypted message
	char *message;
	size_t message_len;

	// mbedtls state
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_cookie_ctx cookie_ctx;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif
};

struct dtls_client_state {
	scewl_id_t server_scewl_id;
	enum dtls_session_status status;
	struct dtls_timers timers;

	// plaintext message to send
	char *message;
	size_t message_len;

	// encrypted data received over SCEWL
	bool data_available;
	char *data;
	size_t data_len;

	// mbedtls state
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;
};

struct dtls_state {
	enum dtls_status status;
	struct dtls_server_state server_state;
	struct dtls_client_state client_state;

	// mbedtls state
	mbedtls_hmac_drbg_context hmac_drbg;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt cert;
	mbedtls_pk_context pkey;
};

void dtls_teardown(struct dtls_state *state);
void dtls_setup(struct dtls_state *state, char *message_buf);
void dtls_send_message(struct dtls_state *state, scewl_id_t dst_id, char *message, size_t message_len);
void dtls_handle_packet(struct dtls_state *state, scewl_id_t src_id, char *data, size_t data_len);
void dtls_check_timers(struct dtls_state *state);

#endif // DTLS_H