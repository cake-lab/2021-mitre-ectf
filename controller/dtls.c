/*
 * Author: Ryan LaPointe <ryan@ryanlapointe.org>
 * Based on "Simple DTLS server demonstration program", which is copyright The Mbed TLS Contributors
 */

#include MBEDTLS_CONFIG_FILE
#include "mbedtls/platform.h"

#include "controller.h"
#include "dtls.h"

#define READ_TIMEOUT_MS 1000   /* 1 second */

/*
 * Callback for printing debug log lines.
 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	mbedtls_printf("[%d] %s:%04d: %s", level, file, line, str);
}

/*
 * Callback used by mbedtls to set a timer.
 */
static void timers_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms) {
	struct timers *timers = (struct timers *) data;
	// timers->start_time = clock();
	timers->int_ms = int_ms;
	timers->fin_ms = fin_ms;
}

/*
 * Callback used by mbedtls to check if a timer has expired.
 */
static int timers_get_delay(void *data) {
	struct timers *timers = (struct timers *) data;
	// clock_t current_time = clock();
	// uint32_t ms_elapsed = (current_time - timers->start_time) * 1000 / CLOCKS_PER_SEC;
	if (timers->fin_ms == 0) {
		return -1;
	// } else if (ms_elapsed >= timers->fin_ms) {
	// 	return 2;
	// } else if (ms_elapsed >= timers->int_ms) {
	// 	return 1;
	}
	return 0;
}

/*
 * Teardown the DTLS server. This is called once when the program is going to exit.
 */
static void dtls_server_teardown(struct dtls_server_state *state) {
	for (int i = 0; i < DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS; i++) {
		mbedtls_ssl_free(&state->sessions[i].ssl);
	}
	mbedtls_ssl_config_free(&state->conf);
	mbedtls_ssl_cookie_free(&state->cookie_ctx);
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
	mbedtls_ctr_drbg_free(&state->ctr_drbg);
	mbedtls_entropy_free(&state->entropy);
}

/*
 * Convert a numeric error code to a descriptive string and print the string.
 */
static void dtls_print_error(int error_code) {
#ifdef MBEDTLS_ERROR_C
	char error_buf[100];
	mbedtls_strerror(error_code, error_buf, 100);
	mbedtls_printf("Last error was: %#06x %s", error_code, error_buf);
#endif
}

/*
 * Handle a fatal error.
 */
static void dtls_fatal_error(struct dtls_state *state, int error_code) {
	dtls_print_error(error_code);
	dtls_teardown(state);
}

/*
 * Initialize a DTLS session.
 * This is called a finite number of times when the DTLS server is starting up.
 * It is NOT called each time a client connects to the server.
 */
static void dtls_server_session_setup(struct dtls_state *dtls_state, struct dtls_server_state *server_state, struct dtls_server_session_state *session_state) {
	int ret;

	mbedtls_ssl_init(&session_state->ssl);
	ret = mbedtls_ssl_setup(&session_state->ssl, &server_state->conf);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_setup returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_timer_cb(&session_state->ssl, &session_state->timers, timers_set_delay, timers_get_delay);
	mbedtls_ssl_set_mtu(&session_state->ssl, SCEWL_MAX_DATA_SZ);

	session_state->valid = false;
}

/*
 * Initialize the DTLS server.
 * This is called once.
 */
static void dtls_server_setup(struct dtls_state *dtls_state, struct dtls_server_state *server_state) {
	int ret;

	mbedtls_ssl_config_init(&server_state->conf);
	mbedtls_ssl_cookie_init(&server_state->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&server_state->cache);
#endif

	mbedtls_printf("Setting up the DTLS data...");

	ret = mbedtls_ssl_config_defaults(&server_state->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_config_defaults returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_rng(&server_state->conf, mbedtls_ctr_drbg_random, &dtls_state->ctr_drbg);
	mbedtls_ssl_conf_dbg(&server_state->conf, my_debug, NULL);
	mbedtls_ssl_conf_read_timeout(&server_state->conf, READ_TIMEOUT_MS);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_conf_session_cache(&server_state->conf, &server_state->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

	mbedtls_ssl_conf_ca_chain(&server_state->conf, dtls_state->cert.next, NULL); // TODO
	ret = mbedtls_ssl_conf_own_cert(&server_state->conf, &dtls_state->cert, &dtls_state->pkey);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_conf_own_cert returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	ret = mbedtls_ssl_cookie_setup(&server_state->cookie_ctx, mbedtls_ctr_drbg_random, &dtls_state->ctr_drbg);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_cookie_setup returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_dtls_cookies(&server_state->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &server_state->cookie_ctx);

	mbedtls_ssl_conf_authmode(&server_state->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	for (int i = 0; i < DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS; i++) {
		dtls_server_session_setup(dtls_state, server_state, &server_state->sessions[i]);
	}

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

	ret = mbedtls_ssl_config_defaults(&client_state->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_config_defaults returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_rng(&client_state->conf, mbedtls_ctr_drbg_random, &dtls_state->ctr_drbg);
	mbedtls_ssl_conf_dbg(&client_state->conf, my_debug, NULL);
	mbedtls_ssl_conf_read_timeout(&client_state->conf, READ_TIMEOUT_MS);

	mbedtls_ssl_conf_ca_chain(&client_state->conf, dtls_state->cert.next, NULL); // TODO
	ret = mbedtls_ssl_conf_own_cert(&client_state->conf, &dtls_state->cert, &dtls_state->pkey);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_conf_own_cert returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_conf_authmode(&client_state->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	mbedtls_ssl_init(&client_state->ssl);
	ret = mbedtls_ssl_setup(&client_state->ssl, &client_state->conf);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_setup returned %#06x", ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_timer_cb(&client_state->ssl, &client_state->timers, timers_set_delay, timers_get_delay);
	mbedtls_ssl_set_mtu(&client_state->ssl, SCEWL_MAX_DATA_SZ);

	mbedtls_printf("ok");
}

/*
 * Initialize things that are common to the DTLS server and client.
 * This is called once.
 */
void dtls_setup(struct dtls_state *state) {
	int ret, len;
	char pers[6];

	mbedtls_x509_crt_init(&state->ca);
	mbedtls_x509_crt_init(&state->cert);
	mbedtls_pk_init(&state->pkey);
	mbedtls_entropy_init(&state->entropy);
	mbedtls_ctr_drbg_init(&state->ctr_drbg);

	/*
	 * Load the certificates and private RSA key
	 */
	mbedtls_printf("Loading certificates and key...");

	/*
	 * This demonstration program uses embedded test certificates.
	 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
	 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
	 */
	ret = mbedtls_x509_crt_parse(&state->ca, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_x509_crt_parse returned %#06x", ret);
		dtls_fatal_error(state, ret);
		return;
	}

	ret = mbedtls_x509_crt_parse(&state->cert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_x509_crt_parse returned %#06x", ret);
		dtls_fatal_error(state, ret);
		return;
	}

	ret = mbedtls_pk_parse_key(&state->pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_pk_parse_key returned %#06x", ret);
		dtls_fatal_error(state, ret);
		return;
	}

	mbedtls_printf("ok");

	/*
	 * Seed the RNG
	 */
	mbedtls_printf("Seeding the random number generator...");

	len = mbedtls_snprintf(pers, 6, "%u", (unsigned int) SCEWL_ID);
	ret = mbedtls_ctr_drbg_seed(&state->ctr_drbg, mbedtls_entropy_func, &state->entropy, (unsigned char *) pers, len);
	if(ret != 0) {
		mbedtls_printf("failed! mbedtls_ctr_drbg_seed returned %#06x", ret);
		dtls_fatal_error(state, ret);
		return;
	}

	mbedtls_printf( "ok" );

	dtls_server_setup(state, &state->server_state);
	dtls_client_setup(state, &state->client_state);
}

/*
 * Send data to the client of an active session.
 */
static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
	if (len > SCEWL_MAX_DATA_SZ) {
		return -1;
	}
	struct dtls_server_session_state *session_state = (struct dtls_server_session_state *) ctx;
	handle_scewl_send((const char *) buf, session_state->client_scewl_id, len);
	return len;
}

/*
 * Receive data from the client of an active session.
 */
static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
	struct dtls_server_session_state *session_state = (struct dtls_server_session_state *) ctx;
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
 * Prepare a previously idle session to be used as an active session with a client.
 */
static void dtls_server_session_startup(struct dtls_state *dtls_state, struct dtls_server_state *server_state, struct dtls_server_session_state *session_state) {
	int ret, len;
	char buf[6];

	mbedtls_ssl_session_reset(&session_state->ssl);

	/* For HelloVerifyRequest cookies */
	len = mbedtls_snprintf(buf, 6, "%u", (unsigned int) session_state->client_scewl_id);
	ret = mbedtls_ssl_set_client_transport_id(&session_state->ssl, (unsigned char *) buf, len);
	if (ret != 0) {
		mbedtls_printf("failed! mbedtls_ssl_set_client_transport_id() returned %#06x", (unsigned int) -ret);
		dtls_fatal_error(dtls_state, ret);
		return;
	}

	mbedtls_ssl_set_bio(&session_state->ssl, session_state, ssl_send, ssl_recv, NULL);

	session_state->data_available = false;
	session_state->message_len = 0;
	session_state->status = HANDSHAKE;
}

/*
 * Give the specified session some data that we received.
 */
static void dtls_server_session_feed(struct dtls_server_session_state *session_state, char *data, uint16_t data_len) {
	session_state->data = data;
	session_state->data_len = data_len;
	session_state->data_available = true;
}

/*
 * Prepare the client to connect to a server.
 */
static void dtls_client_startup(struct dtls_client_state *state, char *message, uint16_t message_len) {
	state->data_available = false;
	state->message = message;
	state->message_len = message_len;
	state->status = HANDSHAKE;
}

/*
 * Give the client session some data that we received.
 */
static void dtls_client_feed(struct dtls_client_state *state, char *data, uint16_t data_len) {
	state->data = data;
	state->data_len = data_len;
	state->data_available = true;
}

/*
 * Do some processing for the specified session.
 */
static void dtls_server_session_run(struct dtls_server_session_state *session_state) {
	int ret;

	if (session_state->status == HANDSHAKE) {
		ret = mbedtls_ssl_handshake(&session_state->ssl);

		if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			mbedtls_printf("hello verification requested");
			session_state->status = DONE;
		} else if (ret == 0) {
			mbedtls_printf("handshake complete");
			session_state->status = READ;
		} else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("failed! mbedtls_ssl_handshake returned %#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			session_state->status = DONE;
		}
	} else if (session_state->status == READ) {
		do {
			ret = mbedtls_ssl_read(&session_state->ssl, (unsigned char *) &session_state->message[session_state->message_len], SCEWL_MAX_DATA_SZ - session_state->message_len);
			if (ret > 0) {
				session_state->message_len += ret;
			}
		} while (ret > 0);
		switch (ret) {
			case MBEDTLS_ERR_SSL_WANT_READ:
				break;
			case MBEDTLS_ERR_SSL_TIMEOUT:
				mbedtls_printf("timeout");
				session_state->status = DONE;
				break;
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
				mbedtls_printf("session was closed gracefully");
				session_state->status = DONE;
				break;
			default:
				mbedtls_printf("mbedtls_ssl_read returned %#06x", (unsigned int) -ret);
				dtls_print_error(ret);
				session_state->status = DONE;
		}
	}

	if (session_state->status == DONE) {
		mbedtls_printf("Closing the connection...");
		// No error checking, the connection might be closed already
		mbedtls_ssl_close_notify(&session_state->ssl);
		mbedtls_printf("done");
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
			mbedtls_printf("handshake complete");
			state->status = WRITE;
		} else if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("failed! mbedtls_ssl_handshake returned %#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			state->status = DONE;
		}
	} else if (state->status == WRITE) {
		pos = 0;
		do {
			ret = mbedtls_ssl_write(&state->ssl, (unsigned char *) &state->message[pos], state->message_len - pos);
			if (ret > 0) {
				pos += ret;
				if (pos == state->message_len) {
					state->status = DONE;
					break;
				}
			}
		} while (ret > 0);
		if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) {
			mbedtls_printf("mbedtls_ssl_write returned %#06x", (unsigned int) -ret);
			dtls_print_error(ret);
			state->status = DONE;
		}
	}

	if (state->status == DONE) {
		mbedtls_printf("Closing the connection...");
		// No error checking, the connection might be closed already
		mbedtls_ssl_close_notify(&state->ssl);
		mbedtls_printf("done");
	}
}

/*
 * Handle a DTLS packet received over the SCEWL bus.
 */
void dtls_handle_packet(struct dtls_state *state, struct scewl_hdr_t header, char *data) {
	int i;

	/*
	 * DTLS client packet handling
	 */

	if (state->client_state.active && state->client_state.server_scewl_id == header.src_id) {
		// Give the session the data that we received
		dtls_client_feed(&state->client_state, data, header.len);
		dtls_client_run(&state->client_state);
		if (state->client_state.status == DONE) {
			mbedtls_printf("Sent message to server %u: %.*s", (unsigned int) state->client_state.server_scewl_id, state->client_state.message_len, state->client_state.message);
			// TODO tell the CPU the message was sent?
			state->client_state.active = false;
		}
	}

	/*
	 * DTLS server packet handling
	 */

	struct dtls_server_session_state *session = NULL;
	// Find the existing session with this client
	for (i = 0; i < DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS; i++) {
		if (state->server_state.sessions[i].valid && state->server_state.sessions[i].client_scewl_id == header.src_id) {
			session = &state->server_state.sessions[i];
		}
	}
	if (session == NULL) {
		// There is no existing session with this client
		// Start a new session with this client
		for (i = 0; i < DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS; i++) {
			if (!state->server_state.sessions[i].valid) {
				state->server_state.sessions[i].valid = true;
				state->server_state.sessions[i].client_scewl_id = header.src_id;
				session = &state->server_state.sessions[i];
				dtls_server_session_startup(state, &state->server_state, session);
			}
		}
	}
	if (session == NULL) {
		// There are too many simultaneous DTLS connections. Drop the packet.
		mbedtls_printf("Too many simultaneous DTLS connections.");
		return;
	}
	if (session->data_available) {
		// Should never happen
		mbedtls_exit(MBEDTLS_EXIT_FAILURE);
	}
	// Give the session the data that we received
	dtls_server_session_feed(session, data, header.len);
	dtls_server_session_run(session);
	if (session->status == DONE) {
		mbedtls_printf("Received message from client %u: %.*s", (unsigned int) session->client_scewl_id, session->message_len, session->message);
		// TODO do something with the message
		session->valid = false;
	}
}

/*
 * This function must be called often.
 */
void dtls_check_timers(struct dtls_state *state) {
	if (state->client_state.active) {
		if (timers_get_delay(&state->client_state.timers) == 2) {
				dtls_client_run(&state->client_state);
			}
	}
	for (int i = 0; i < DTLS_SERVER_MAX_SIMULTANEOUS_CONNECTIONS; i++) {
		if (state->server_state.sessions[i].valid) {
			if (timers_get_delay(&state->server_state.sessions[i].timers) == 2) {
				dtls_server_session_run(&state->server_state.sessions[i]);
			}
		}
	}
}
