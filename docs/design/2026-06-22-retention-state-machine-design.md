# Design: Retention State Machine (SPARK trusted core)

Date: 2026-06-22
Status: Implemented and verified
Spec source of truth: `docs/SPEC.md` (Trusted Core, Retention State Machine).

## Goal

First unit of the SPARK-verified trusted core. It enforces, by formal proof, the
spec's mandatory invariants:

```
A retained object can never be deleted before expiry.
A retention period can never be shortened (it may be extended).
```

Scope (per spec): object lock creation, governance mode, compliance mode, and
retention expiration. Legal hold is marked "future" in the spec and is out of
scope.

## Principles

- Ada 2022; this module is `SPARK_Mode => On` throughout.
- Pure logic: no I/O, no clock access, no heap. This is what makes the invariants
  provable end to end.
- `gnatprove` discharging all verification conditions is the primary acceptance
  gate; tests are the safety net.

## Module boundary

Package `Dezhan.Trusted_Core.Retention` exposes pure types and functions with no
dependency on any OS facility. Time is supplied by the caller (the Clock
Integrity Guard); persistence is a separate concern handled elsewhere.

## State model

```
type Lock_Mode is (Unlocked, Governance, Compliance);
Trusted_Time is the shared type from Dezhan.Trusted_Core.Times.
type Authorization is record
   Bypass_Governance : Boolean := False;   -- audited capability (governance only)
end record;
type Retention_Lock is record
   Mode         : Lock_Mode    := Unlocked;
   Retain_Until : Trusted_Time := 0;
   Created_At   : Trusted_Time := 0;
end record;
```

## Time model

Every time-dependent operation takes `Now : Trusted_Time` as a parameter. The
state machine never reads a clock. `Trusted_Time` is a bounded integer range so
no arithmetic overflow conditions arise (the machine only compares times).

## Operations and the invariants as contracts

- `Create_Lock (Mode, Retain_Until, Now)`: `Pre` requires `Mode /= Unlocked` and
  `Retain_Until >= Now`; `Post` sets the fields as given.
- `Extend_Retention (L, New_Until)`: returns `L` with
  `Retain_Until = Trusted_Time'Max (L.Retain_Until, New_Until)`. The
  unconditional `Post` proves `result.Retain_Until >= L.Retain_Until`, so by
  construction the function cannot shorten retention.
- `Request_Extension (L, New_Until)`: returns the extended lock plus whether the
  request moved the expiry forward.
- `Can_Delete (L, Now, Auth)`: the deletion policy. Unlocked is always
  deletable; compliance requires `Now >= Retain_Until` with no override;
  governance allows the same or an audited bypass.
- Ghost lemma `Lemma_Compliance_Is_Absolute`: in compliance mode before expiry,
  no authorization can permit deletion.

## Verification strategy

- `gnatprove --level=2` must report 0 unproved checks: all preconditions,
  postconditions, and the ghost lemma discharged.
- Behavioural tests (`tests/test_retention.adb`) assert no operation sequence
  shortens retention or permits early deletion in compliance mode, plus
  governance bypass behavior.

## Acceptance criteria

1. The library and tests compile.
2. `gnatprove` reports 0 unproved checks for `Dezhan.Trusted_Core.Retention`.
3. `test_retention` runs green.
