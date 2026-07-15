/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * RTT-based bonded-leg muting hysteresis state machine.  Kept in a small
 * standalone header so the transition logic can be unit-tested in isolation,
 * without constructing full peer objects or starting sender threads.
 */

#ifndef RIST_RTT_MUTE_H
#define RIST_RTT_MUTE_H

#include <stdbool.h>
#include <stdint.h>

enum rist_rtt_mute_action
{
	RIST_RTT_MUTE_NONE = 0,    /* no state change this step */
	RIST_RTT_MUTE_DROP = 1,    /* transition active -> muted */
	RIST_RTT_MUTE_RESTORE = 2, /* transition muted -> active */
};

struct rist_rtt_mute_state
{
	bool muted;             /* leg currently out of the unique-payload rotation */
	bool pending;           /* a transition condition is currently held */
	uint64_t pending_since; /* tick the pending condition first held */
};

/* Advance the hysteresis machine for one leg by one sample.
 *
 * All RTT/time arguments share one unit (RIST_CLOCK ticks):
 *   smoothed_rtt : the leg's smoothed (EWMA) round-trip time
 *   drop         : ceiling; staying above it for settle mutes the leg
 *   restore      : low-water; staying below it for settle restores the leg
 *   settle       : dwell required before either transition (both directions)
 *   now          : monotonic tick
 *
 * The drop/restore split (restore < drop) plus the settle dwell give the
 * hysteresis that stops a link flapping in and out of the bond.  A drop of 0
 * disables muting and restores the leg if it was muted.  Returns the
 * transition taken this step (NONE if the state is unchanged) and updates
 * *st in place. */
static inline enum rist_rtt_mute_action
rist_rtt_mute_step(struct rist_rtt_mute_state *st, uint64_t smoothed_rtt,
                   uint64_t drop, uint64_t restore, uint64_t settle, uint64_t now)
{
	if (drop == 0) {
		st->pending = false;
		if (st->muted) {
			st->muted = false;
			return RIST_RTT_MUTE_RESTORE;
		}
		return RIST_RTT_MUTE_NONE;
	}

	bool condition = st->muted ? (smoothed_rtt < restore)
	                           : (smoothed_rtt > drop);
	if (!condition) {
		st->pending = false;
		return RIST_RTT_MUTE_NONE;
	}
	if (!st->pending) {
		st->pending = true;
		st->pending_since = now;
		return RIST_RTT_MUTE_NONE;
	}
	if (now - st->pending_since < settle)
		return RIST_RTT_MUTE_NONE;

	st->pending = false;
	if (st->muted) {
		st->muted = false;
		return RIST_RTT_MUTE_RESTORE;
	}
	st->muted = true;
	return RIST_RTT_MUTE_DROP;
}

#endif /* RIST_RTT_MUTE_H */
