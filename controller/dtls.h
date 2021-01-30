/*
 * Author: Ryan LaPointe <ryan@ryanlapointe.org>
 */

#include <stdbool.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

/*
 * We can have multiple incoming (server) DTLS connections at a time.
 * We can have only one outgoing (client) DTLS connection at a time.
 */
#define DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS 5

enum dtls_session_status {
	HANDSHAKE,
	READ,
	WRITE,
	DONE
};

struct timers {
	// clock_t start_time;
	uint32_t int_ms;
	uint32_t fin_ms;
};

struct dtls_server_session_state {
	bool valid;
	scewl_id_t client_scewl_id;
	enum dtls_session_status status;
	struct timers timers;

	// encrypted data received over SCEWL
	bool data_available;
	char *data;
	uint16_t data_len;

	// decrypted message
	char message[SCEWL_MAX_DATA_SZ];
	uint16_t message_len;

	// mbedtls state
	mbedtls_ssl_context ssl;
};

struct dtls_server_state {
	struct dtls_server_session_state sessions[DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS];

	// mbedtls state
	mbedtls_ssl_config conf;
	mbedtls_ssl_cookie_ctx cookie_ctx;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif
};

struct dtls_client_state {
	bool active;
	scewl_id_t server_scewl_id;
	enum dtls_session_status status;
	struct timers timers;

	// plaintext message to send
	char message[SCEWL_MAX_DATA_SZ];
	uint16_t message_len;

	// encrypted data received over SCEWL
	bool data_available;
	char *data;
	uint16_t data_len;

	// mbedtls state
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;
};

struct dtls_state {
	struct dtls_server_state server_state;
	struct dtls_client_state client_state;

	// mbedtls state
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt cert;
	mbedtls_pk_context pkey;
};

void dtls_teardown(struct dtls_state *state);
void dtls_setup(struct dtls_state *state);
void dtls_handle_packet(struct dtls_state *state, struct scewl_hdr_t header, char *data);
void dtls_check_timers(struct dtls_state *state);
