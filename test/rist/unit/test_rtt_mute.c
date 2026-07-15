/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the RTT-based bonded-leg muting hysteresis state machine
 * (rist_rtt_mute_step).  Drives sample sequences through the pure function
 * and asserts the drop/restore transitions and dwell behaviour.  No library
 * link or threads required. */

#include "../../../src/rist-rtt-mute.h"

#include <stdint.h>
#include <stdio.h>

/* Thresholds in abstract "tick" units; the production caller uses RIST_CLOCK
 * ticks but the machine is unit-agnostic. */
#define DROP     500
#define RESTORE  400
#define SETTLE   3

static int failures;

static void expect(const char *name, enum rist_rtt_mute_action got,
                   enum rist_rtt_mute_action want, bool muted, bool want_muted)
{
	if (got != want || muted != want_muted) {
		fprintf(stderr, "FAIL: %s -> action %d muted %d (want action %d muted %d)\n",
		        name, got, muted, want, want_muted);
		failures++;
	}
}

int main(void)
{
	/* A leg that never crosses the ceiling stays active. */
	{
		struct rist_rtt_mute_state st = {0};
		enum rist_rtt_mute_action a = RIST_RTT_MUTE_NONE;
		for (uint64_t t = 0; t < 10; t++)
			a = rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, t);
		expect("stays_active_below_ceiling", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Over the ceiling but not long enough to satisfy the dwell: no drop. */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 0); /* arm pending */
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 1); /* dwell not met */
		expect("no_drop_before_settle", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Sustained over the ceiling past the dwell: drop. */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 0);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 1);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 2);
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 3); /* now-since == SETTLE */
		expect("drop_after_settle", a, RIST_RTT_MUTE_DROP, st.muted, true);
	}

	/* A transient dip back under the ceiling resets the dwell (anti-flap). */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 0);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 1);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, 2); /* dip: clears pending */
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, 3); /* re-arm, no drop yet */
		expect("dip_resets_dwell", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Hysteresis: while muted, RTT between restore and drop does NOT restore. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		enum rist_rtt_mute_action a = RIST_RTT_MUTE_NONE;
		for (uint64_t t = 0; t < 10; t++)
			a = rist_rtt_mute_step(&st, 450, DROP, RESTORE, SETTLE, t); /* in the band */
		expect("no_restore_in_hysteresis_band", a, RIST_RTT_MUTE_NONE, st.muted, true);
	}

	/* Sustained below the restore low-water past the dwell: restore. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, 0);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, 1);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, 2);
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, 3);
		expect("restore_after_settle", a, RIST_RTT_MUTE_RESTORE, st.muted, false);
	}

	/* drop == 0 disables the feature and force-restores a muted leg. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 9999, 0, RESTORE, SETTLE, 0);
		expect("disabled_forces_restore", a, RIST_RTT_MUTE_RESTORE, st.muted, false);
	}

	/* drop == 0 on an already-active leg is a no-op. */
	{
		struct rist_rtt_mute_state st = {0};
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 9999, 0, RESTORE, SETTLE, 0);
		expect("disabled_active_noop", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
