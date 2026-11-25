# Record specification, draft 0.1

Status: draft. It will change as the threat model and the measurements are finished.

## Goals

1. Every model answer gets one record.
2. A record reveals no input or output text.
3. Any change to a record, any deletion in the middle and any reordering is detectable.
4. An auditor can verify a chain without access to content.
5. A reviewer who holds the original text can confirm that it belongs to a record.

## Keys

- `chain_key`: 32 random bytes. Used to authenticate records and links. Held by the system operator and by auditors who verify chains.
- `content_key`: 32 random bytes. Used to create tags of input and output. Not needed for chain verification. Held only by people who may match original text to records.

The two keys are separate so that chain verification does not give the ability to test guesses about content.

## Record

One JSON object per line:

| Field | Meaning |
|---|---|
| `version` | Format version, currently 1 |
| `index` | Position in the chain, starting at 0 |
| `timestamp` | UTC time, ISO 8601 |
| `model_id` | Identifier of the model |
| `params` | Object with the generation settings |
| `input_tag` | `HMAC-SHA256(content_key, "in" 0x00 input_bytes)` as hex |
| `output_tag` | `HMAC-SHA256(content_key, "out" 0x00 output_bytes)` as hex |
| `key_id` | Identifier of the key set in use |
| `prev` | `hash` of the previous record, 64 zeros for the first |
| `hash` | `HMAC-SHA256(chain_key, canonical(record without hash))` as hex |

`canonical` is JSON with sorted keys, no spaces and UTF-8 encoding.

## Verification

For each record in order: check `index`, check `prev` against the previous `hash`, recompute `hash` from the other fields and compare in constant time. Any mismatch fails the chain.

## Known limits (draft)

- Removing records from the end of a chain leaves a valid shorter chain. Planned fix: periodic checkpoints that are signed or stored elsewhere.
- Whoever holds `chain_key` can create a valid chain. Planned fix: asymmetric signatures for checkpoints, so verifiers do not need to hold a secret that allows forging.
- Short or guessable inputs can be tested by someone holding `content_key`. This is by design for reviewers. Keep `content_key` restricted.
- Matching an answer to its record needs the exact output bytes. Whether outputs of reduced-precision models can be reproduced exactly is the subject of the planned measurements.
