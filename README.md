# Verifiable inference records

A tamper-evident, content-free audit record for answers of self-hosted language models.

Organisations that run language models on their own servers need to prove afterwards what an AI system produced. A plain log either stores complete prompts and answers, which is a data protection problem, or stores too little to prove anything. This project creates one record per model answer that cannot be changed later and does not reveal the content.

## Status

Early prototype (version 0.0.1). Not security reviewed. Do not use in production. The reference code in `vir.py` shows the record format and the chain check. Planned work is listed below.

## How it works

Each record contains:

- a keyed tag of the input and a keyed tag of the output (no plaintext),
- the model identifier and settings,
- a time stamp,
- the hash of the previous record.

The records form a chain stored as one JSON object per line. Any change, deletion in the middle or reordering breaks the chain and is found by the verifier. An auditor can check the chain without seeing any content. A reviewer who holds the original text can check that it matches a record.

See `SPECIFICATION.md` for the exact format and the known limits.

## Try it

Requires Python 3.9 or newer, no other packages.

```
python3 -m unittest discover -s tests -v
```

Write records:

```python
import vir
writer = vir.ChainWriter("chain.jsonl", chain_key, content_key)
writer.append("my-model", {"bits": 8}, input_bytes, output_bytes)
```

Verify a chain from the command line, with the chain key stored as hex in a file:

```
python3 vir.py verify chain.jsonl --chain-key-file chain.key
```

## Open research question

Models run at reduced numeric precision (8 bit and 4 bit) to fit small servers. It is not known how much this weakens exact reproducibility of an output, which decides how a record can be matched to its answer. A measurement study with synthetic prompts is planned. Results will be published here with all scripts and raw data.

## Planned work

1. Public specification and threat model
2. Reproducibility measurements at 16, 8 and 4 bit
3. Core library, key rotation and signed checkpoints, independent verifier
4. Integration layer for open-weight model servers, overhead measurements
5. Security tests, documentation for data protection officers
6. Version 1.0 and technical report

## Licence

MIT, see `LICENSE`. Contributions are welcome once the specification is public.
