/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Coverage for the listener-side cname re-association introduced
 * for upstream issue #188 (NAT source-port rebind on a calling
 * receiver).
 *
 * Topology:
 *   sender(listener, 127.0.0.1:LISTEN_PORT) <-- receiver(caller, src=PORT_A) round 1
 *                                           <-- receiver(caller, src=PORT_B) round 2
 *
 * Both receivers use the same cname so they look like the same
 * logical caller to the sender.  The expected distinct-caller
 * count on the sender depends on whether encryption is configured:
 *
 *   plaintext  -> 2 distinct callers  (gate refused to migrate; the
 *                                      plaintext recovery path is the
 *                                      receiver-side socket rebind,
 *                                      covered by
 *                                      test_caller_socket_rebind.c)
 *   psk        -> 1 distinct caller   (encryption-gated migration
 *                                      fires; the new source tuple
 *                                      is absorbed into the existing
 *                                      peer record)
 *
 * The test passes in both modes when the observed count matches
 * the expected count.  A mismatch indicates either a regression in
 * the encryption gate (plaintext silently migrated -> 1 instead of
 * 2) or in the migration logic itself (psk failed to migrate ->
 * 2 instead of 1).
 *
 * Usage:
 *   test_nat_port_rebind [psk]
 *
 * Exit codes:
 *   0  - observed count matched expected count for the chosen mode
 *   1  - count mismatch (regression in gate or in migration logic)
 *   2  - round 1 handshake never completed (test setup broken)
 *  99  - test setup error (logging, ctx create, etc.)
 */

#include "librist/librist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#define usleep(x) Sleep((x)/1000)
#else
#include <unistd.h>
#endif

static struct rist_logging_settings *log_settings = NULL;

/* Each distinct rist_peer pointer on the listener side represents
 * one logical caller arrival (the callback gates on
 * send_first_connection_event so duplicates per peer do not fire). */
#define MAX_TRACKED_PEERS 16
static struct {
	struct rist_peer *seen[MAX_TRACKED_PEERS];
	int count;
} tracker;
static pthread_mutex_t tracker_lock = PTHREAD_MUTEX_INITIALIZER;

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
	(void)arg;
	if (status == RIST_CONNECTION_ESTABLISHED ||
	    status == RIST_CLIENT_CONNECTED) {
		pthread_mutex_lock(&tracker_lock);
		bool seen = false;
		for (int i = 0; i < tracker.count; i++) {
			if (tracker.seen[i] == peer) { seen = true; break; }
		}
		if (!seen && tracker.count < MAX_TRACKED_PEERS) {
			tracker.seen[tracker.count++] = peer;
			fprintf(stderr, ">> sender CONNECTED (peer=%p, "
			                "distinct_callers=%d)\n",
			        (void *)peer, tracker.count);
		}
		pthread_mutex_unlock(&tracker_lock);
	} else if (status == RIST_CONNECTION_TIMED_OUT ||
	           status == RIST_CLIENT_TIMED_OUT) {
		fprintf(stderr, ">> sender TIMED_OUT (peer=%p)\n", (void *)peer);
	}
}

static struct rist_ctx *start_receiver_with_local_port(const char *url) {
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0)
		return NULL;
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0) {
		rist_destroy(rx);
		return NULL;
	}
	struct rist_peer *peer = NULL;
	if (rist_peer_create(rx, &peer, pcfg) != 0) {
		free(pcfg);
		rist_destroy(rx);
		return NULL;
	}
	free(pcfg);
	if (rist_start(rx) != 0) {
		rist_destroy(rx);
		return NULL;
	}
	return rx;
}

int main(int argc, char *argv[]) {
	bool use_psk = (argc > 1 && strcmp(argv[1], "psk") == 0);
	const char *crypto_suffix = use_psk ? "&secret=testkey1234&aes-type=128" : "";
	int listen_port = use_psk ? 19998 : 20998;
	char tx_url[256];
	char rx_url[256];
	snprintf(tx_url, sizeof(tx_url),
	         "rist://@127.0.0.1:%d?session-timeout=30000&keepalive-interval=1000%s",
	         listen_port, crypto_suffix);

	memset(&tracker, 0, sizeof(tracker));

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb,
	                     NULL, NULL, stderr) != 0) {
		fprintf(stderr, "logging setup failed\n");
		return 99;
	}

	/* sender, listener mode, MAIN profile, no encryption.
	 * session-timeout is set well above the inter-round gap so the
	 * round-1 peer record is still in the listener's child list when
	 * the round-2 packets arrive but has been silent long enough to
	 * cross the cname-reassociation safeguard window. */
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0) {
		fprintf(stderr, "sender ctx create failed\n");
		return 99;
	}
	if (rist_connection_status_callback_set(tx, sender_status_cb, NULL) != 0) {
		fprintf(stderr, "status cb set failed\n");
		rist_destroy(tx);
		return 99;
	}
	fprintf(stderr, "== mode: %s, listen port %d ==\n",
	        use_psk ? "PSK encrypted" : "plaintext", listen_port);
	struct rist_peer_config *tx_pcfg = NULL;
	if (rist_parse_address2(tx_url, (void *)&tx_pcfg) != 0) {
		fprintf(stderr, "sender url parse failed\n");
		rist_destroy(tx);
		return 99;
	}
	struct rist_peer *tx_peer = NULL;
	if (rist_peer_create(tx, &tx_peer, tx_pcfg) != 0) {
		fprintf(stderr, "sender peer create failed\n");
		free(tx_pcfg);
		rist_destroy(tx);
		return 99;
	}
	free(tx_pcfg);
	if (rist_start(tx) != 0) {
		fprintf(stderr, "sender start failed\n");
		rist_destroy(tx);
		return 99;
	}
	usleep(200000); /* let listener bind */

	/* round 1: receiver caller, source port 20001, cname "rebind-test".
	 * session-timeout matches the sender so the receiver-side
	 * silence-recovery path does not fire during this Fix #1 test. */
	fprintf(stderr, "\n== round 1: receiver from local-port=20001 ==\n");
	snprintf(rx_url, sizeof(rx_url),
	         "rist://127.0.0.1:%d?local-port=20001&cname=rebind-test"
	         "&session-timeout=30000&keepalive-interval=1000%s",
	         listen_port, crypto_suffix);
	struct rist_ctx *rx1 = start_receiver_with_local_port(rx_url);
	if (!rx1) {
		fprintf(stderr, "rx1 setup failed\n");
		rist_destroy(tx);
		return 99;
	}

	/* let handshake complete */
	usleep(3000000);

	pthread_mutex_lock(&tracker_lock);
	int after_round1 = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	fprintf(stderr, "after round 1: distinct callers on sender = %d\n",
	        after_round1);

	/* tear down round-1 receiver, wait long enough that its peer
	 * record on the sender side has been silent past the
	 * cname-reassociation safeguard window (2 keepalive intervals),
	 * then start round-2 with a different source port and the same
	 * cname.  The sibling is still well within session_timeout, so
	 * it is still in the listener's child list when round 2 arrives. */
	fprintf(stderr, "\n== destroying rx1; waiting for silence ==\n");
	rist_destroy(rx1);
	usleep(3000000); /* > 2 * keepalive_interval, < session_timeout */

	fprintf(stderr, "\n== round 2: receiver from local-port=20002, "
	                "same cname ==\n");
	snprintf(rx_url, sizeof(rx_url),
	         "rist://127.0.0.1:%d?local-port=20002&cname=rebind-test"
	         "&session-timeout=30000&keepalive-interval=1000%s",
	         listen_port, crypto_suffix);
	struct rist_ctx *rx2 = start_receiver_with_local_port(rx_url);
	if (!rx2) {
		fprintf(stderr, "rx2 setup failed\n");
		rist_destroy(tx);
		return 99;
	}

	/* let round-2 handshake complete */
	usleep(3000000);

	pthread_mutex_lock(&tracker_lock);
	int after_round2 = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	fprintf(stderr, "\n== after round 2: distinct callers on sender = %d ==\n",
	        after_round2);

	rist_destroy(rx2);
	rist_destroy(tx);
	free(log_settings);

	if (after_round1 == 0) {
		fprintf(stderr, "INDETERMINATE: round 1 handshake never completed.\n");
		return 2;
	}

	int expected = use_psk ? 1 : 2;
	if (after_round2 == expected) {
		if (use_psk)
			fprintf(stderr, "PASS: psk migration absorbed the new "
			                "tuple into the existing peer record "
			                "(distinct_callers=%d as expected).\n",
			        after_round2);
		else
			fprintf(stderr, "PASS: encryption gate refused migration "
			                "in plaintext (distinct_callers=%d as "
			                "expected; receiver-side recovery is "
			                "covered separately).\n", after_round2);
		return 0;
	}
	if (use_psk)
		fprintf(stderr, "FAIL: psk migration did not fire; "
		                "distinct_callers=%d, expected 1.\n",
		        after_round2);
	else
		fprintf(stderr, "FAIL: encryption gate did NOT refuse "
		                "migration in plaintext; distinct_callers=%d, "
		                "expected 2.\n", after_round2);
	return 1;
}
