# Risk model

Risk is a transparent engineering prioritization, not a scientifically calibrated probability.

The current score starts from algorithm quantum status, then adjusts for purpose, public exposure, stated confidentiality lifetime, HNDL relevance, production/test classification, and evidence confidence. Key establishment and encryption receive more confidentiality weight; signatures and certificates receive authenticity/longevity weight. Test or fixture code is reduced by two points. Low or unknown evidence confidence reduces authority.

Thresholds map the score to `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`; non-Shor PQC/symmetric observations retain rule policy levels. Every finding includes severity, confidence, rationale, evidence hash/type, affected source span, purpose, migration urgency, and next action.

Defaults are conservative but explicit: exposure, data lifetime, trust lifetime, migration complexity, and HNDL context are unknown unless supplied. Dead code is not proven by AST and is not silently discarded. Dependency and protocol context are retained when observed but never fabricated.
