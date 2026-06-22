# Design: Clock Integrity Guard (SPARK trusted core)

Date: 2026-06-22
Status: Implemented and verified
Spec source of truth: `docs/SPEC.md` (Clock Integrity Guard; Clock Manipulation).

## Goal

Second unit of the SPARK trusted core. Produce the `Trusted_Time` the Retention
State Machine consumes, while enforcing the mandatory invariant:

```
System time manipulation cannot invalidate active locks.
```

Concrete attack (per spec): move the system clock forward to expire locks early.
Mitigation: trusted-time validation and monotonic time enforcement.

## Core idea

`CLOCK_REALTIME` is untrusted. Trusted time advances only by elapsed time from a
monotonic source (`CLOCK_BOOTTIME`); realtime is used only for anomaly detection,
never to compute the time value that gates retention. Therefore the trusted-time
value is provably independent of `CLOCK_REALTIME`: manipulating the system clock
has zero effect on it.

Decisions: trust anchor is a software monotonic clock plus a persisted high-water
mark (no special hardware; pluggable for TPM or RTC later). Behavior on
manipulation or uncertainty is fail-closed toward immutability: never advance
past the trusted monotonic bound, latch a seal, and never err toward deletion.

## Shared time type

`Dezhan.Trusted_Core.Times` defines `Trusted_Time` (whole seconds since an opaque
monotonic epoch). Retention uses it so the Guard's output feeds
`Create_Lock`/`Can_Delete` directly. Trusted time is monotonic-elapsed, not
wall-clock; absolute calendar time is a display-only concern handled elsewhere.

## Pure SPARK state machine: `Dezhan.Trusted_Core.Clock_Guard`

```
type Anomaly_Kind is (None, Monotonic_Reset, Rollback, Forward_Jump);
type Guard_State  is record
   Floor     : Trusted_Time;  -- monotonic non-decreasing trusted time
   Last_Mono : Trusted_Time;  -- last monotonic reading
   Last_Real : Trusted_Time;  -- last realtime reading (detection only)
   Anomaly   : Anomaly_Kind;
   Sealed    : Boolean;       -- latched on manipulation (Rollback/Forward_Jump)
end record;
type Clock_Sample is record
   Mono, Realtime : Trusted_Time;  -- Realtime is UNTRUSTED
   Boot_Changed   : Boolean;       -- monotonic source reset (reboot)
end record;
```

Visible expression functions pin the exact value: `Mono_Delta` is 0 across a
reboot or an impossible backward monotonic reading, else `Mono - Last_Mono`;
`Advanced_Floor` is `Floor + Mono_Delta` saturating at `Trusted_Time'Last`.

`Tick` advances `Floor` to `Advanced_Floor`, records the readings, and classifies
anomalies from realtime: a reboot flags `Monotonic_Reset` (does not seal, reboots
are normal); realtime deviating from `Last_Real + Mono_Delta` by more than
`Tolerance` flags `Forward_Jump` or `Rollback` and latches `Sealed`.

## Invariants proved by gnatprove (postconditions on `Tick`)

1. `Floor = Advanced_Floor (S, Sample)`: exact, so the value is a function of the
   monotonic inputs alone.
2. Monotonic: `Floor >= S.Floor`.
3. Bounded advance: `Floor - S.Floor <= Mono_Delta (S, Sample)`.
4. Seal latches: `S.Sealed` implies result `Sealed`.
5. Lemma `Lemma_Realtime_Independent`: samples agreeing on `Mono` and
   `Boot_Changed` but differing in `Realtime`/`Tolerance` yield the same `Floor`.
   This is the formal statement of "system time manipulation cannot invalidate
   active locks."

## Boundary (untrusted, not proved): `Dezhan.Platform.Clock`

A `SPARK_Mode => Off` adapter binds `clock_gettime(CLOCK_BOOTTIME/REALTIME)` via
`Interfaces.C` and builds a `Clock_Sample`. Within a single process there is no
reboot, so `Boot_Changed = False`; cross-reboot detection and durable persistence
of `Guard_State` are deferred (see `docs/NOTES.md`).

## Acceptance criteria

1. The library and tests compile.
2. `gnatprove` reports 0 unproved checks (Clock Guard and Retention).
3. `test_retention` and `test_clock_guard` run green, including the integration
   test that a realtime forward jump cannot expire a compliance lock.
