# ADR-0055: An anchor resolves the drift alert about its segment

- Status: accepted
- Date: 2026-09-27
- Deciders: the operator

## Context

ADR-0044 made resolving an alert one deliberate human act: `innsegl
resolve-alert`, run from a trusted host, and never an action on the dashboard.
doc 06 §4.5 says an alert stays "until the underlying condition clears".

For one kind of alert, those two disagree. When a segment cannot be anchored,
the sealer raises a `ledger_drift_detected` whose subject is that segment's
`segment_sealed` event. When a later cycle anchors it, the condition has
cleared, and the fact is public: the transparency-log index is on the chain.
Nothing connected the two. Measured on 2026-09-27: three such alerts stayed on
the Overview for eleven days after their segments were anchored at log indexes
0, 17 and 18.

## Decision

When the sealer appends the superseding `segment_sealed` that anchors a
segment, it resolves every open `ledger_drift_detected` whose
`subject_event_id` is that segment's original `segment_sealed` event. It writes
the resolution as `innsegl-sealer`, with the segment, its position range and
its log index as the reason.

- Only that subject, and only drift alerts. An `unattributed_signature_detected`
  alert, or a drift alert about anything else, is still a person's to resolve.
- A resolution already recorded is kept. Nothing is overwritten.
- A failure to resolve is reported in the cycle's view and does not stop the
  cycle. The anchor stands either way.
- The alert event is never touched (I4). Only `innsegl.alert_resolutions`
  gains a row, as ADR-0044 defined.

The dashboard stays read-only. For every other open alert, its detail page
shows the exact `innsegl resolve-alert` command to run (ADR-0054).

## Alternatives considered

- **A Resolve button on the dashboard.** It needs an operator login and a write
  path in the API, which ends the read-only posture doc 05 and ADR-0044 rest on.
  Not ruled out for later, but it would need its own ADR.
- **Hide an alert once its segment is anchored, without a resolution row.** The
  API would then compute "open" from two sources, and the record of why the
  alert closed would exist nowhere.
- **Leave it to the operator.** That is what produced eleven days of alerts
  about a fault that was gone.

## Consequences

- `ADR-0044` is amended for this one case: a resolution may be written by the
  component whose work cleared the cause, when that work is itself on the chain.
- `innsegl_appender`, the sealer's role, needs INSERT on
  `innsegl.alert_resolutions`, which #323 grants.
- Exit cost: removing this means drift alerts about anchored segments stay
  open again until a person resolves them.
