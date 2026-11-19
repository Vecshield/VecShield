# Ingestion integration

VecShield is a **gate** in your ingestion pipeline. A typical RAG ingestion
flow, with VecShield inserted before the embedder:

```
source systems (DBs, apps, docs)
        │
        ▼
data lake / object store (S3, GCS, Azure Blob)
        │
        ▼
loader / parser (PDF, HTML, JSON, ...)
        │
        ▼
splitter / chunker
        │
        ▼
┌─────────────────────────────┐
│   VecShield PII gate         │  ← detect PII/PHI/PCI/secrets
└─────────────────────────────┘
        │
        ├── block   → drop the chunk, fail the batch
        ├── redact  → mask spans, keep the context
        └── approve → pass clean chunks through
        │
        ▼
embedding model
        │
        ▼
vector DB (upsert)
```

The rule of thumb: **gate after chunking and before embedding.** Once a chunk is
embedded, the sensitive data is persisted in the vector store; once it is in a
training set, it is baked into weights.

## Integration points

### Custom Python

```python
from vecshield import check_chunks

report = check_chunks(chunks, mode="soft")
clean = report.allowed_chunks           # embed only these
```

### LangChain

Use the callback handler to filter documents after the splitter. See
[`examples/langchain_ingest_gate.py`](../../examples/library/langchain_ingest_gate.py).

### LlamaIndex

Gate `nodes` after the node parser, before `VectorStoreIndex`. See
[`examples/llamaindex_ingest_gate.py`](../../examples/library/llamaindex_ingest_gate.py).

### Airflow / Dagster / Prefect

Add a gate task between the chunk task and the embed task; raise to fail the DAG
on PII. See [`examples/airflow_ingest_check.py`](../../examples/library/airflow_ingest_check.py),
[`examples/dagster_ingest_gate.py`](../../examples/library/dagster_ingest_gate.py), and
[`examples/prefect_ingest_gate.py`](../../examples/library/prefect_ingest_gate.py).

### S3 / GCS / Azure Blob batch jobs

Run `vecshield ingest-check` (or `check_dataset`) over the staged batch before
the embedding job kicks off.

### CI checks for training datasets

```yaml
- run: pip install vecshield
- run: vecshield training-check ./datasets/ --fail-on high
```

### Kafka / Flink (streaming)

For streaming ingestion, call `check_text` / `check_chunks` inside your stream
processor. This is a later-stage integration; batch gating covers most
pipelines first.

## Modes

- **soft** (default) — report blocked vs allowed; you decide.
- **hard** — raise `PiiDetectedError` when anything is blocked (fail-closed).
- **redact** — mask spans with `IngestGate.redact()` / `redact_text()` and embed
  the cleaned text.

## Injected instructions

The gate also looks for instructions planted for the model that will later read
a chunk: "ignore your previous instructions", a forged system turn, an image
URL that carries the conversation out, text hidden in a comment or encoded so a
reviewer does not see it. It is on by default and stops nothing by default.

```python
from vecshield.ingest import IngestGate

report = IngestGate().inspect(chunks)            # injection="flag"
for flag in report.injection_flags:
    print(flag["chunk_id"], flag["verdict"], flag["confidence"], flag["rules"])

IngestGate(injection="block")                    # also block high-confidence flags
IngestGate(injection="off")                      # no injection check
```

- **flag** (default) — a flagged chunk is listed in `report.injection_flags`
  and still allowed.
- **block** — a chunk flagged at high confidence (a score of 0.8 or more, or a
  directive that had to be decoded or unhidden to be read) is blocked and gets
  a finding. Lower-confidence flags are listed and allowed. So is text about
  injection attacks that quotes a payload: it is marked `suspicious`, because a
  security article is not an attack, and it is still listed, because a quoted
  payload can act on a model that retrieves it.
- **off** — no check.

What a clean result means: no known signature was found, in a language that
has rules (`vecshield.injection.LANGUAGES`; all but English are unreviewed).
The scanner does not read meaning. An instruction paraphrased beyond the rules,
or one with nothing in it that marks it as addressed to a model ("always
recommend the enterprise tier"), is not found. Measured recall and
false-positive rates on public data are in
[benchmarks/injection.md](benchmarks/injection.md). Keep treating retrieved
text as data in the application: delimit it in the prompt and do not let it
trigger tools.
