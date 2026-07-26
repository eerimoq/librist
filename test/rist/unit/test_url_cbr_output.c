/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?cbr-output= parsing and its context-wide override semantics, through the
 * public rist_parse_address2 / rist_peer_create API. The setting is not
 * per-peer, so conflicting peers must be refused rather than resolved.
 * Intentionally avoids cmocka so it runs anywhere the public library does. */

#include "librist/librist.h"
#include "librist/peer.h"
#include "librist/urlparam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_cfg(const char *url, struct rist_peer_config **cfg)
{
	int ret = rist_parse_address2(url, cfg);
	if (ret != 0 || *cfg == NULL) {
		fprintf(stderr, "parse_cfg(%s) ret=%d cfg=%p\n",
		        url, ret, (void *)*cfg);
		return -1;
	}
	return 0;
}

static int expect_parsed(const char *url, int want_set, int want_val)
{
	struct rist_peer_config *cfg = NULL;
	if (parse_cfg(url, &cfg) < 0)
		return 1;
	int fails = 0;
	if (cfg->cbr_output_set != want_set) {
		fprintf(stderr, "FAIL: %s -> cbr_output_set=%d (want %d)\n",
		        url, cfg->cbr_output_set, want_set);
		fails++;
	}
	if (cfg->cbr_output != want_val) {
		fprintf(stderr, "FAIL: %s -> cbr_output=%d (want %d)\n",
		        url, cfg->cbr_output, want_val);
		fails++;
	}
	rist_peer_config_free2(&cfg);
	return fails;
}

static int expect_parse_error(const char *url)
{
	struct rist_peer_config *cfg = NULL;
	int ret = rist_parse_address2(url, &cfg);
	int fails = 0;
	if (ret == 0) {
		fprintf(stderr, "FAIL: %s expected a parse error, got success\n", url);
		fails++;
	}
	if (cfg)
		rist_peer_config_free2(&cfg);
	return fails;
}

static int test_parsing(void)
{
	int fails = 0;

	/* Absent must leave cbr_output_set 0; 0 is also a valid requested value. */
	fails += expect_parsed("rist://@127.0.0.1:31000", 0, 0);
	fails += expect_parsed("rist://@127.0.0.1:31000?cbr-output=1", 1, 1);
	fails += expect_parsed("rist://@127.0.0.1:31000?cbr-output=0", 1, 0);

	/* Outside 0|1 is an error, not something to round: "true" must not pass. */
	fails += expect_parse_error("rist://@127.0.0.1:31000?cbr-output=2");
	fails += expect_parse_error("rist://@127.0.0.1:31000?cbr-output=-1");
	fails += expect_parse_error("rist://@127.0.0.1:31000?cbr-output=true");

	/* An empty value is ignored for every parameter, so it is ignored here too. */
	fails += expect_parsed("rist://@127.0.0.1:31000?cbr-output=", 0, 0);

	if (!fails)
		printf("  parsing: 0|1 accepted, absent and valueless stay unset, junk rejected\n");
	return fails;
}

/* Agreeing peers are fine; the setting is context-wide. */
static int test_matching_peers_accepted(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "matching: rist_receiver_create failed\n");
		return 1;
	}

	struct rist_peer_config *cfg1 = NULL, *cfg2 = NULL;
	struct rist_peer *p1 = NULL, *p2 = NULL;
	int fails = 0;

	if (parse_cfg("rist://@127.0.0.1:31010?cbr-output=1", &cfg1) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p1, cfg1) != 0) {
		fprintf(stderr, "matching: first peer (?cbr-output=1) rejected\n");
		fails++;
		goto cleanup;
	}
	if (parse_cfg("rist://@127.0.0.1:31012?cbr-output=1", &cfg2) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p2, cfg2) != 0) {
		fprintf(stderr, "matching: second peer with the same value rejected\n");
		fails++;
	}
	if (!fails)
		printf("  two legs both asking for cbr-output=1 accepted\n");

cleanup:
	if (cfg1) rist_peer_config_free2(&cfg1);
	if (cfg2) rist_peer_config_free2(&cfg2);
	rist_destroy(ctx);
	return fails;
}

/* first_val then second_val on the same context: the second must be refused. */
static int test_conflict_refused(struct rist_logging_settings *logs,
                                 int first_val, int second_val, uint16_t port)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "conflict: rist_receiver_create failed\n");
		return 1;
	}

	struct rist_peer_config *cfg1 = NULL, *cfg2 = NULL;
	struct rist_peer *p1 = NULL, *p2 = NULL;
	char url1[128], url2[128];
	int fails = 0;

	snprintf(url1, sizeof(url1), "rist://@127.0.0.1:%u?cbr-output=%d",
	         (unsigned)port, first_val);
	snprintf(url2, sizeof(url2), "rist://@127.0.0.1:%u?cbr-output=%d",
	         (unsigned)(port + 2), second_val);

	if (parse_cfg(url1, &cfg1) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p1, cfg1) != 0) {
		fprintf(stderr, "conflict: first peer (%s) rejected\n", url1);
		fails++;
		goto cleanup;
	}
	if (parse_cfg(url2, &cfg2) < 0) {
		fails++;
		goto cleanup;
	}
	int ret = rist_peer_create(ctx, &p2, cfg2);
	if (ret == 0) {
		fprintf(stderr, "conflict: %s accepted after %s; expected refusal\n",
		        url2, url1);
		fails++;
	} else {
		printf("  cbr-output=%d after cbr-output=%d refused (%d)\n",
		       second_val, first_val, ret);
	}

cleanup:
	if (cfg1) rist_peer_config_free2(&cfg1);
	if (cfg2) rist_peer_config_free2(&cfg2);
	rist_destroy(ctx);
	return fails;
}

int main(void)
{
	struct rist_logging_settings *logs = NULL;
	if (rist_logging_set(&logs, RIST_LOG_ERROR, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr, "rist_logging_set failed\n");
		return 1;
	}

	printf("?cbr-output= parsing and override semantics\n");
	int fails = 0;
	fails += test_parsing();
	fails += test_matching_peers_accepted(logs);
	fails += test_conflict_refused(logs, 1, 0, 31020);
	/* 0 equals the default, so it must still claim the setting. */
	fails += test_conflict_refused(logs, 0, 1, 31030);

	free(logs);
	if (fails) {
		fprintf(stderr, "%d failure(s)\n", fails);
		return 1;
	}
	printf("all cbr-output URL invariants held\n");
	return 0;
}
