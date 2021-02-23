/*
 * Author: Ryan LaPointe <ryan@ryanlapointe.org>
 * Based on "Simple DTLS server demonstration program", which is copyright The Mbed TLS Contributors
 */

#include MBEDTLS_CONFIG_FILE
#include "mbedtls/platform.h"
#include "controller.h"
#include "sed_rand.h"
#include "sed_secrets.h"
#include "timers.h"
#include "dtls.h"

#define HS_TIMEOUT_MS_MIN 7000
#define HS_TIMEOUT_MS_MAX 60000
#define SCEWL_MTU 1000


/*
 * Callback for printing debug log lines.
 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	mbedtls_printf("[%d] %s:%04d: %s", level, file, line, str);
}

/*
 * Teardown the DTLS server. This is called once when the program is going to exit.
 */
static void dtls_server_teardown(struct dtls_server_state *state) {
	mbedtls_ssl_free(&state->ssl);
	mbedtls_ssl_config_free(&state->conf);
#ifdef MBEDTLS_SSL_DTLS_HELLO_VERIFY
	mbedtls_ssl_cookie_free(&state->cookie_ctx);
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&state->cache);
#endif
}

/*
 * Teardown the DTLS client. This is called once when the program is going to exit.
 */
static void dtls_client_teardown(struct dtls_client_state *state) {
	mbedtls_ssl_free(&state->ssl);
	mbedtls_ssl_config_free(&state->conf);
}

/*
 * Teardown the DTLS server and client. This is called once when the program is going to exit.
 */
void dtls_teardown(struct dtls_state *state) {
	dtls_server_teardown(&state->server_state);
	dtls_client_teardown(&state->client_state);
	mbedtls_x509_crt_free(&state->ca);
	mbedtls_x509_crt_free(&state->cert);
	mbedtls_pk_free(&state->pkey);
	mbedtls_hmac_drbg_free(&state->hmac_drbg);
}

/*
 * Convert a numeric error code to a descriptive string and print the string.
 */
static void dtls_print_error(int error_code) {
#ifdef MBEDTLS_ERROR_C
	char error_buf[100];
	mbedtls_strerror(error_code, error_buf, 100);
	mbedtls_printf("Last error was: %#10x (-%#06x) %s", error_code, (unsigned int) -error_code, error_buf);
#endif
}

/*
 * Handle a fatal error.
 */
static void dtls_fatal_error(struct dtls_state *state, int error_code) {
	state->status = FATAL_ERROR;
	dtls_print_error(error_code);
	dtls_teardown(state);
}

/*
 * Initialize the DTLS server.
 * This is called once.
 */
static void dtls_server_setup(struct dtls_state *dtls_state, struct dtls_server_state *server_state) {
	int ret;

	mbedtls_ssl_config_init(&server_state->conf);
#ifdef MBEDTLS_SSL_DTLS_HELLO_VERIFY
	mbedtls_ssl_cookie_init(&server_state->cookie_ctx);
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&server_state->cache);
#endif

	mbedtls_printf("Setting up the DTLS data...");

	ret = mbedtls_ssl_config_defaults(&server_state->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_config_defaults returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_rng(&server_state->conf, mbedtls_hmac_drbg_random, &dtls_state->hmac_drbg);
	mbedtls_ssl_conf_dbg(&server_state->conf, my_debug, NULL);
	mbedtls_ssl_conf_handshake_timeout(&server_state->conf, HS_TIMEOUT_MS_MIN, HS_TIMEOUT_MS_MAX);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_conf_session_cache(&server_state->conf, &server_state->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

	mbedtls_ssl_conf_ca_chain(&server_state->conf, &dtls_state->ca, NULL); // TODO use CRL?
	ret = mbedtls_ssl_conf_own_cert(&server_state->conf, &dtls_state->cert, &dtls_state->pkey);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_conf_own_cert returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

#ifdef MBEDTLS_SSL_DTLS_HELLO_VERIFY
	ret = mbedtls_ssl_cookie_setup(&server_state->cookie_ctx, mbedtls_hmac_drbg_random, &dtls_state->hmac_drbg);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_cookie_setup returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_dtls_cookies(&server_state->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &server_state->cookie_ctx);
#endif

	mbedtls_ssl_conf_authmode(&server_state->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	mbedtls_ssl_init(&server_state->ssl);
	ret = mbedtls_ssl_setup(&server_state->ssl, &server_state->conf);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_setup returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_timer_cb(&server_state->ssl, &server_state->timers, timers_set_delay, timers_get_delay);
	mbedtls_ssl_set_mtu(&server_state->ssl, SCEWL_MTU);

	mbedtls_printf("ok");
}

/*
 * Initialize the DTLS client.
 * This is called once.
 */
static void dtls_client_setup(struct dtls_state *dtls_state, struct dtls_client_state *client_state) {
	int ret;

	mbedtls_ssl_config_init(&client_state->conf);

	mbedtls_printf("Setting up the DTLS data...");

	ret = mbedtls_ssl_config_defaults(&client_state->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_config_defaults returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_rng(&client_state->conf, mbedtls_hmac_drbg_random, &dtls_state->hmac_drbg);
	mbedtls_ssl_conf_dbg(&client_state->conf, my_debug, NULL);
	mbedtls_ssl_conf_handshake_timeout(&client_state->conf, HS_TIMEOUT_MS_MIN, HS_TIMEOUT_MS_MAX);

	mbedtls_ssl_conf_ca_chain(&client_state->conf, &dtls_state->ca, NULL); // TODO use CRL?
	ret = mbedtls_ssl_conf_own_cert(&client_state->conf, &dtls_state->cert, &dtls_state->pkey);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_conf_own_cert returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_authmode(&client_state->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	mbedtls_ssl_init(&client_state->ssl);
	ret = mbedtls_ssl_setup(&client_state->ssl, &client_state->conf);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_setup returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_timer_cb(&client_state->ssl, &client_state->timers, timers_set_delay, timers_get_delay);
	mbedtls_ssl_set_mtu(&client_state->ssl, SCEWL_MTU);

	mbedtls_printf("ok");
}

/*
 * Initialize things that are common to the DTLS server and client.
 * This is called once.
 */
void dtls_setup(struct dtls_state *state, char *message_buf) {
	int ret;
	uint32_t flags;
	char scewl_id_str[16];
	int scewl_id_str_len;

	state->status = IDLE;
	state->server_state.message = message_buf;

	scewl_id_str_len = mbedtls_snprintf(scewl_id_str, 16, "%u_PROVISION", (unsigned int) SCEWL_ID);

	mbedtls_x509_crt_init(&state->ca);
	mbedtls_x509_crt_init(&state->cert);
	mbedtls_pk_init(&state->pkey);
	mbedtls_hmac_drbg_init(&state->hmac_drbg);

	/*
	 * Load the certificates and private RSA key
	 */
	mbedtls_printf("Loading certificates and key...");

	/*
	 * This demonstration program uses embedded test certificates.
	 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
	 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
	 */
	ret = mbedtls_x509_crt_parse(&state->ca, (const unsigned char *) provision_ca, strlen(provision_ca)+1);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_x509_crt_parse returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(state, ret);
		return;
	}

	ret = mbedtls_x509_crt_parse(&state->cert, (const unsigned char *) sed_provision_crt, strlen(sed_provision_crt)+1);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_x509_crt_parse returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(state, ret);
		return;
	}

	ret = mbedtls_pk_parse_key(&state->pkey, (const unsigned char *) sed_provision_key, strlen(sed_provision_key)+1, NULL, 0);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_pk_parse_key returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(state, ret);
		return;
	}

	ret = mbedtls_x509_crt_verify(&state->cert, &state->ca, NULL, scewl_id_str, &flags, NULL, NULL);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_x509_crt_verify returned -%#06x with flags %#10x", (unsigned int) -ret, flags);
		dtls_fatal_error(state, ret);
		return;
	}

	mbedtls_printf("ok");

	/*
	 * Set up RNG
	 */
	ret = rng_module_setup(&state->hmac_drbg, (unsigned char *) scewl_id_str, scewl_id_str_len);
	if(ret != 0) {
		dtls_fatal_error(state, ret);
		return;
	}

	mbedtls_printf( "ok" );

	dtls_server_setup(state, &state->server_state);
	if (state->status == FATAL_ERROR) {
		return;
	}
	dtls_client_setup(state, &state->client_state);
}

/*
 * Send data to the client of an active session.
 */
static int dtls_server_ssl_send(void *ctx, const unsigned char *buf, size_t len) {
	if (len > SCEWL_MTU) {
		return -1;
	}
	struct dtls_server_state *state = (struct dtls_server_state *) ctx;
	send_msg(RAD_INTF, SCEWL_ID, state->client_scewl_id, len, (const char *) buf);
	return len;
}

/*
 * Receive data from the client of an active session.
 */
static int dtls_server_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
	struct dtls_server_state *state = (struct dtls_server_state *) ctx;
	if (!state->data_available) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	size_t bytes_to_copy = len <= state->data_len ? len : state->data_len;
	memcpy(buf, state->data, bytes_to_copy);
	state->data_len -= bytes_to_copy;
	state->data += bytes_to_copy;
	if (state->data_len == 0) {
		state->data_available = false;
	}
	return bytes_to_copy;
}

/*
 * Send data to the server of an active session.
 */
static int dtls_client_ssl_send(void *ctx, const unsigned char *buf, size_t len) {
	if (len > SCEWL_MTU) {
		return -1;
	}
	struct dtls_client_state *session_state = (struct dtls_client_state *) ctx;
	if (session_state->channel == SCEWL) {
		send_msg(RAD_INTF, SCEWL_ID, session_state->server_scewl_id, len, (const char *) buf);
	} else if (session_state->channel == SSS) {
		send_msg(SSS_INTF, SCEWL_ID, session_state->server_scewl_id, len, (const char *) buf);
	}
	return len;
}

/*
 * Receive data from the server of an active session.
 */
static int dtls_client_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
	struct dtls_client_state *session_state = (struct dtls_client_state *) ctx;
	if (!session_state->data_available) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	size_t bytes_to_copy = len <= session_state->data_len ? len : session_state->data_len;
	memcpy(buf, session_state->data, bytes_to_copy);
	session_state->data_len -= bytes_to_copy;
	session_state->data += bytes_to_copy;
	if (session_state->data_len == 0) {
		session_state->data_available = false;
	}
	return bytes_to_copy;
}

/*
 * Prepare the server for a connection from a client.
 */
static void dtls_server_startup(struct dtls_state *dtls_state, struct dtls_server_state *server_state) {
	int ret, len;
	char buf[6];

	ret = mbedtls_ssl_session_reset(&server_state->ssl);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_session_reset returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	/* For HelloVerifyRequest cookies */
#ifdef MBEDTLS_SSL_DTLS_HELLO_VERIFY
	len = mbedtls_snprintf(buf, 6, "%u", (unsigned int) server_state->client_scewl_id);
	ret = mbedtls_ssl_set_client_transport_id(&server_state->ssl, (unsigned char *) buf, len);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_set_client_transport_id returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}
#endif

	mbedtls_ssl_set_bio(&server_state->ssl, server_state, dtls_server_ssl_send, dtls_server_ssl_recv, NULL);

	server_state->data_available = false;
	server_state->message_len = 0;
	server_state->status = HANDSHAKE;
}

/*
 * Give the server some data that we received.
 */
static void dtls_server_feed(struct dtls_server_state *server_state, char *data, size_t data_len) {
	server_state->data = data;
	server_state->data_len = data_len;
	server_state->data_available = true;
}

/*
 * Prepare the client to connect to a server.
 */
static void dtls_client_startup(struct dtls_state *dtls_state, struct dtls_client_state *client_state, char *message, size_t message_len) {
	int ret;

	ret = mbedtls_ssl_session_reset(&client_state->ssl);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_session_reset returned -%#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_bio(&client_state->ssl, client_state, dtls_client_ssl_send, dtls_client_ssl_recv, NULL);
	client_state->data_available = false;
	client_state->message = message;
	client_state->message_len = message_len;
	client_state->status = HANDSHAKE;
}

/*
 * Give the client some data that we received.
 */
static void dtls_client_feed(struct dtls_client_state *state, char *data, size_t data_len) {
	state->data = data;
	state->data_len = data_len;
	state->data_available = true;
}

/*
 * Do some processing for the server session.
 */
static void dtls_server_run(struct dtls_server_state *server_state) {
	int ret;

	if (server_state->status == HANDSHAKE) {
		ret = mbedtls_ssl_handshake(&server_state->ssl);

		if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			mbedtls_printf("hello verification requested");
			server_state->status = DONE;
			return;
		} else if (ret == 0) {
			mbedtls_printf("Handshake complete.");
			server_state->status = READ;
		} else if (ret == MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO) {
			// The packet was probably not a hello packet at all.
			// It was probably from a session that we already considered closed.
			// Simply ignore it.
			server_state->status = DONE;
			return;
		} else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("failed! mbedtls_ssl_handshake returned -%#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			server_state->status = DONE;
		}
	} else if (server_state->status == READ) {
		do {
			ret = mbedtls_ssl_read(&server_state->ssl, (unsigned char *) &server_state->message[server_state->message_len], SCEWL_MAX_DATA_SZ - server_state->message_len);
			if (ret > 0) {
				server_state->message_len += ret;
			}
		} while (ret > 0);
		switch (ret) {
			case MBEDTLS_ERR_SSL_WANT_READ:
				break;
			case MBEDTLS_ERR_SSL_TIMEOUT:
				mbedtls_printf("timeout");
				server_state->status = DONE;
				break;
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
				mbedtls_printf("session was closed gracefully");
				server_state->status = DONE;
				break;
			default:
				mbedtls_printf("mbedtls_ssl_read returned -%#06x", (unsigned int) -ret);
				dtls_print_error(ret);
				server_state->status = DONE;
		}
	}

	if (server_state->status == DONE) {
		mbedtls_printf("Closing the connection...");
		// No error checking, the connection might be closed already
		mbedtls_ssl_close_notify(&server_state->ssl);
		mbedtls_printf("done");
		if (server_state->message_len > 0) {
			mbedtls_printf("Received message from client %u: %.*s", (unsigned int) server_state->client_scewl_id, server_state->message_len, server_state->message);
			// Hand off the received message to the CPU
			handle_scewl_recv(server_state->message, server_state->client_scewl_id, server_state->message_len);
		}
	}
}

/*
 * Do some processing for the client session.
 */
static void dtls_client_run(struct dtls_client_state *state) {
	int ret, pos;

	if (state->status == HANDSHAKE) {
		ret = mbedtls_ssl_handshake(&state->ssl);

		if (ret == 0) {
			mbedtls_printf("Handshake complete.");
			state->status = WRITE;
		} else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("failed! mbedtls_ssl_handshake returned -%#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			state->status = DONE;
		}
	}
	if (state->status == WRITE) {
		pos = 0;
		do {
			ret = mbedtls_ssl_write(&state->ssl, (unsigned char *) &state->message[pos], state->message_len - pos);
			if (ret > 0) {
				pos += ret;
				if (pos == state->message_len) {
					if (state->channel == SSS) {
						mbedtls_printf("Sent request. Receiving response...");
						state->status = READ;
						state->message_len = 0;
					} else {
						state->status = DONE;
					}
					break;
				}
			}
		} while (ret > 0);
		if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("mbedtls_ssl_write returned -%#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			state->status = DONE;
		}
	} else if (state->status == READ) {
		do {
			ret = mbedtls_ssl_read(&state->ssl, (unsigned char *) &state->message[state->message_len], SCEWL_MAX_DATA_SZ - state->message_len);
			if (ret > 0) {
				state->message_len += ret;
				if (state->message_len == sizeof(scewl_sss_msg_t)) {
					state->status = DONE;
					break;
				}
			}
		} while (ret > 0);
		if (ret < 0) {
			switch (ret) {
				case MBEDTLS_ERR_SSL_WANT_READ:
					break;
				case MBEDTLS_ERR_SSL_TIMEOUT:
					mbedtls_printf("timeout");
					state->status = DONE;
					break;
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					mbedtls_printf("session was closed gracefully");
					state->status = DONE;
					break;
				default:
					mbedtls_printf("mbedtls_ssl_read returned -%#06x", (unsigned int) -ret);
					dtls_print_error(ret);
					state->status = DONE;
			}
		}
	}
	if (state->status == DONE) {
		mbedtls_printf("Closing the connection...");
		// No error checking, the connection might be closed already
		mbedtls_ssl_close_notify(&state->ssl);
		mbedtls_printf("done");
		if (state->channel == SCEWL) {
			mbedtls_printf("Sent message to server %u: %.*s", (unsigned int) state->server_scewl_id, state->message_len, state->message);
		} else if (state->channel == SSS) {
			mbedtls_printf("Received response.");
			handle_sss_recv(state->message, state->message_len);
		}
	}
}

/*
 * Send a message to another SED.
 */
void dtls_send_message(struct dtls_state *state, scewl_id_t dst_id, char *message, size_t message_len) {
	switch (state->status) {
		case FATAL_ERROR:
			mbedtls_printf("The DTLS subsystem is in FATAL_ERROR state.");
			return;
		case SENDING_MESSAGE:
		case RECEIVING_MESSAGE:
		case TALKING_TO_SSS:
			// Should never happen
			mbedtls_printf("Attempted to send a message while there is an active session.");
			dtls_fatal_error(state, MBEDTLS_EXIT_FAILURE);
			return;
		case IDLE:
			state->status = SENDING_MESSAGE;
			state->client_state.channel = SCEWL;
			state->client_state.server_scewl_id = dst_id;
			dtls_client_startup(state, &state->client_state, message, message_len);
			dtls_client_run(&state->client_state);
			return;
	}
}

/*
 * Send a message to the SSS.
 */
void dtls_send_message_to_sss(struct dtls_state *state, char *message, size_t message_len) {
	switch (state->status) {
		case FATAL_ERROR:
			mbedtls_printf("The DTLS subsystem is in FATAL_ERROR state.");
			return;
		case SENDING_MESSAGE:
		case RECEIVING_MESSAGE:
		case TALKING_TO_SSS:
			// Should never happen
			mbedtls_printf("Attempted to send a message while there is an active session.");
			dtls_fatal_error(state, MBEDTLS_EXIT_FAILURE);
			return;
		case IDLE:
			state->status = TALKING_TO_SSS;
			state->client_state.channel = SSS;
			state->client_state.server_scewl_id = SCEWL_SSS_ID;
			dtls_client_startup(state, &state->client_state, message, message_len);
			dtls_client_run(&state->client_state);
			return;
	}
}

/*
 * Handle a DTLS packet received over the SCEWL bus.
 */
void dtls_handle_packet(struct dtls_state *state, scewl_id_t src_id, char *data, size_t data_len) {
	switch (state->status) {
		case FATAL_ERROR:
			mbedtls_printf("The DTLS subsystem is in FATAL_ERROR state.");
			return;
		case SENDING_MESSAGE:
		case TALKING_TO_SSS:
			// DTLS client packet handling
			if (state->client_state.server_scewl_id == src_id) {
				// Give the session the data that we received
				dtls_client_feed(&state->client_state, data, data_len);
				dtls_client_run(&state->client_state);
				if (state->client_state.status == DONE) {
					state->status = IDLE;
				}
			} else {
				// Drop packet
				mbedtls_printf("Dropping packet from %u", src_id);
			}
			return;
		case IDLE:
			// Assume the packet is a new incoming session
			state->server_state.client_scewl_id = src_id;
			dtls_server_startup(state, &state->server_state);
			state->status = RECEIVING_MESSAGE;
			// Fall through
		case RECEIVING_MESSAGE:
			// DTLS server packet handling
			if (state->server_state.client_scewl_id == src_id) {
				// Give the session the data that we received
				dtls_server_feed(&state->server_state, data, data_len);
				dtls_server_run(&state->server_state);
				if (state->server_state.status == DONE) {
					state->status = IDLE;
				}
			} else {
				// Drop packet
				mbedtls_printf("Dropping packet from %u", src_id);
			}
			return;
	}
}

/*
 * This function must be called often.
 */
void dtls_check_timers(struct dtls_state *state) {
	switch (state->status) {
		case SENDING_MESSAGE:
		case TALKING_TO_SSS:
			if (timers_get_delay(&state->client_state.timers) == 2) {
					dtls_client_run(&state->client_state);
					if (state->client_state.status == DONE) {
						state->status = IDLE;
					}
			}
			break;
		case RECEIVING_MESSAGE:
			if (timers_get_delay(&state->server_state.timers) == 2) {
				dtls_server_run(&state->server_state);
				if (state->server_state.status == DONE) {
					state->status = IDLE;
				}
			}
			break;
		case IDLE:
		case FATAL_ERROR:
			break;
	}
}
