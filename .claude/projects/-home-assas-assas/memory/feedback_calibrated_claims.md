---
name: feedback-calibrated-claims
description: User requires evidence-calibrated wording in findings — label hypotheses as hypotheses and state exactly what a metric does/doesn't prove.
metadata:
  type: feedback
---

When reporting investigation results, the user (Assas team) rejects wording that
overstates certainty: calling a plausible mechanism "confirmed/مؤكد", or treating
one metric as proof of a whole pathway (e.g. `kernel_drops=0` only rules out
AF_PACKET-layer drops on the host — not the switch SPAN port or the rest of the
mirror path).

**Why:** their reports go into sprint evidence docs; an overclaimed cause can
drive wrong decisions (e.g. tuning dedup or deleting alerts for a non-bug).

**How to apply:** separate *facts* (counts, 1:1 log matches) from
*interpretation*; mark interpretations "consistent with / plausible hypothesis,
not confirmed"; for any "X proves Y" statement, state the layer/scope X actually
covers. Mark untestable checks "pending / not live-tested", never pass. Related:
[[feedback-plan-rigor]].
