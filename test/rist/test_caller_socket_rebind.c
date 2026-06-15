/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Coverage for the receiver-caller socket rebind introduced for
 * upstream issue #188 (silent recovery from sender silence on
 * plaintext and shared-PSK callers; SRP callers recover via the
 * listener-side reassociation path instead).
 *
 * Usage:
 *   test_caller_socket_rebind [psk]
 *
 * Topology (single hop, in-process):
 *   sender(listener, 127.0.0.1:PORT) <-- receiver(caller, plain|psk)
 *
 * Sequence:
 *   1. Spin up sender + receiver, wait for handshake.
 *   2. Snapshot the receiver peer's local socket fd and local port.
 *   3. Destroy the sender.  Receiver now sees silence.
 *   4. Wait > session_timeout.
 *   5. Re-create a sender on the same listen port.
 *   6. Wait a couple more session_timeouts for the rebind +
 *      handshake to fire.
 *   7. PASS when the receiver peer is still alive, its local port
 *      has changed (rebind happened), rebind_attempts > 0, and the
 *      new sender's listener saw the reconnected caller.
 *
 * Without the rebind, the receiver peer is killed and never
 * recovers without operator intervention.
 *
 * Exit codes:
 *   0  - rebind fired AND new sender saw the reconnected caller
 *   1  - receiver was killed or never rebound (regression)
 *   2  - test setup never reached an initial handshake
 *  99  - setup error
 */

#include "librist/librist.h"
#include "rist-private.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

static struct rist_logging_settings *log_settings = NULL;

static struct {
	bool first_seen;
	bool second_seen;
	struct rist_peer *second_peer;
} cb_state;
static pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;

static int log_cb(void *arg, enum rist_log_level level, const char *msg) {
	(void)arg;
	const char *tag = level <= RIST_LOG_ERROR ? "E" :
	                  level <= RIST_LOG_WARN  ? "W" :
	                  level <= RIST_LOG_INFO  ? "I" : "D";
	fprintf(stderr, "%s| %s", tag, msg);
	return 0;
}

static void sender_status_cb(void *arg, struct rist_peer *peer,
                             enum rist_connection_status status)
{
	bool *which = (bool *)arg;
	if (status == RIST_CONNECTION_ESTABLISHED ||
	    status == RIST_CLIENT_CONNECTED) {
		pthread_mutex_lock(&cb_lock);
		*which = true;
		if (which == &cb_state.second_seen)
			cb_state.second_peer = peer;
		pthread_mutex_unlock(&cb_lock);
		fprintf(stderr, ">> %s sender CONNECTED (peer=%p)\n",
		        which == &cb_state.first_seen ? "first" : "second",
		        (void *)peer);
	}
}

static struct rist_ctx *spawn_sender(int port, void *cb_arg, const char *crypto) {
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0)
		return NULL;
	if (rist_connection_status_callback_set(tx, sender_status_cb, cb_arg) != 0) {
		rist_destroy(tx);
		return NULL;
	}
	char url[256];
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=2000&keepalive-interval=500%s",
	         port, crypto);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0) {
		rist_destroy(tx);
		return NULL;
	}
	struct rist_peer *peer = NULL;
	if (rist_peer_create(tx, &peer, pcfg) != 0) {
		free(pcfg);
		rist_destroy(tx);
		return NULL;
	}
	free(pcfg);
	if (rist_start(tx) != 0) {
		rist_destroy(tx);
		return NULL;
	}
	return tx;
}

int main(int argc, char *argv[]) {
	bool use_psk = (argc > 1 && strcmp(argv[1], "psk") == 0);
	const char *crypto_suffix = use_psk ? "&secret=testkey1234&aes-type=128" : "";
	const int listen_port = use_psk ? 22001 : 22000;
	memset(&cb_state, 0, sizeof(cb_state));

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb,
	                     NULL, NULL, stderr) != 0) {
		fprintf(stderr, "logging setup failed\n");
		return 99;
	}

	fprintf(stderr, "== mode: %s ==\n", use_psk ? "PSK encrypted" : "plaintext");

	/* spawn the first sender */
	fprintf(stderr, "== spawning first sender on :%d ==\n", listen_port);
	struct rist_ctx *tx1 = spawn_sender(listen_port, &cb_state.first_seen, crypto_suffix);
	if (!tx1) {
		fprintf(stderr, "sender create failed\n");
		return 99;
	}
	usleep(200000);

	/* spawn the receiver caller, no local-port pin, short
	 * session_timeout so the test runs fast. */
	fprintf(stderr, "== spawning receiver caller ==\n");
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0) {
		fprintf(stderr, "rx ctx create failed\n");
		rist_destroy(tx1);
		return 99;
	}
	char rx_url[256];
	snprintf(rx_url, sizeof(rx_url),
	         "rist://127.0.0.1:%d?session-timeout=2000&keepalive-interval=500"
	         "&cname=fix2-test%s",
	         listen_port, crypto_suffix);
	struct rist_peer_config *rx_pcfg = NULL;
	if (rist_parse_address2(rx_url, (void *)&rx_pcfg) != 0) {
		fprintf(stderr, "rx url parse failed\n");
		rist_destroy(rx); rist_destroy(tx1);
		return 99;
	}
	struct rist_peer *rx_peer = NULL;
	if (rist_peer_create(rx, &rx_peer, rx_pcfg) != 0) {
		fprintf(stderr, "rx peer create failed\n");
		free(rx_pcfg); rist_destroy(rx); rist_destroy(tx1);
		return 99;
	}
	free(rx_pcfg);
	if (rist_start(rx) != 0) {
		fprintf(stderr, "rx start failed\n");
		rist_destroy(rx); rist_destroy(tx1);
		return 99;
	}

	/* wait for handshake */
	usleep(2000000);
	pthread_mutex_lock(&cb_lock);
	bool first = cb_state.first_seen;
	pthread_mutex_unlock(&cb_lock);
	if (!first) {
		fprintf(stderr, "INDETERMINATE: first sender never saw a "
		                "handshake; test setup is broken.\n");
		rist_destroy(rx); rist_destroy(tx1);
		free(log_settings);
		return 2;
	}

	int original_sd = rx_peer->sd;
	uint16_t original_port = rx_peer->local_port;
	fprintf(stderr, "== handshake complete: receiver peer sd=%d "
	                "local_port=%u ==\n",
	        original_sd, (unsigned)original_port);

	/* destroy the sender: receiver now sees silence */
	fprintf(stderr, "== destroying first sender, waiting for silence "
	                "(> session_timeout) ==\n");
	rist_destroy(tx1);
	usleep(4000000); /* > 2 * session_timeout to make sure the
	                  * receiver-side timeout check ran. */

	bool dead_now = rx_peer->dead;
	uint32_t rebinds = rx_peer->rebind_attempts;
	int sd_now = rx_peer->sd;
	uint16_t port_now = rx_peer->local_port;
	fprintf(stderr, "== after silence window: rebind_attempts=%"PRIu32
	                ", dead=%d, sd=%d (was %d), local_port=%u (was %u) ==\n",
	        rebinds, dead_now, sd_now, original_sd,
	        (unsigned)port_now, (unsigned)original_port);

	if (rebinds == 0) {
		fprintf(stderr, "FAIL: rebind never fired; rebind_attempts is 0.\n");
		rist_destroy(rx);
		free(log_settings);
		return 1;
	}
	if (dead_now) {
		fprintf(stderr, "FAIL: receiver peer was killed; rebind should "
		                "have kept it alive across the silence.\n");
		rist_destroy(rx);
		free(log_settings);
		return 1;
	}
	if (port_now == original_port) {
		fprintf(stderr, "FAIL: local port did not change; rebind did "
		                "not actually re-bind the socket.\n");
		rist_destroy(rx);
		free(log_settings);
		return 1;
	}

	/* bring the sender back up; expect the rebound caller to find it */
	fprintf(stderr, "== bringing a new sender up on :%d ==\n", listen_port);
	struct rist_ctx *tx2 = spawn_sender(listen_port, &cb_state.second_seen, crypto_suffix);
	if (!tx2) {
		fprintf(stderr, "second sender create failed\n");
		rist_destroy(rx);
		free(log_settings);
		return 99;
	}

	/* give the next keepalive + handshake time to land */
	usleep(4000000);

	pthread_mutex_lock(&cb_lock);
	bool second = cb_state.second_seen;
	pthread_mutex_unlock(&cb_lock);

	rist_destroy(rx);
	rist_destroy(tx2);
	free(log_settings);

	if (!second) {
		fprintf(stderr, "FAIL: rebind happened (port %u->%u, %"PRIu32
		                " attempts) but the new sender never saw the "
		                "reconnected caller; handshake never completed.\n",
		        (unsigned)original_port, (unsigned)port_now, rebinds);
		return 1;
	}

	fprintf(stderr, "PASS: receiver auto-rebound from local_port %u to %u "
	                "after %"PRIu32" attempt(s) and the new sender saw the "
	                "reconnected caller without operator intervention.\n",
	        (unsigned)original_port, (unsigned)port_now, rebinds);
	return 0;
}
