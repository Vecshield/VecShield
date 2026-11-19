# The optional injection classifier

The injection scanner reads signatures. It can also ask a pre-trained
classifier for a second opinion, which finds instructions the rules have no
signature for: paraphrases, social engineering, languages without rules. This
page says how to turn it on, what it will and will not do, and what it costs.

It is off unless you configure it. Nothing is downloaded for you.

## What it does to a result

- The classifier reads the same canonical text the rules read (invisible
  characters, look-alike letters and tag characters undone first).
- If its probability reaches the model's threshold, the text is **flagged**,
  with a span naming the model and the probability.
- A flag that rests on the classifier alone is never **high confidence**. The
  ingest gate does not block on it, and the integrity finding reports it at
  medium severity. A model's opinion cannot be read and checked the way a rule
  can, so it raises a chunk for review and stops there.
- It never lowers what the rules found.
- Below its threshold it only changes the order of unflagged text, which is
  what improves ranking measures such as AUC.
- If it is configured and cannot be loaded, the layer reads `unavailable` and
  the check is partial. A layer that was asked for and did not run is not a
  clean pass.

## Turn it on

```bash
pip install "vecshield[injection-ml]"        # onnxruntime and tokenizers; no PyTorch
```

Put the model's ONNX file and `tokenizer.json` in a directory, and point the
scanner at it:

```bash
export VECSHIELD_INJECTION_MODEL_DIR=/opt/vecshield/models/horizon-guard-small
```

The ingest gate, `vecshield injection-check`, and the server's integrity scan
all pick it up. In code:

```python
from vecshield import check_injection
from vecshield.injection import OnnxClassifier

classifier = OnnxClassifier("/opt/vecshield/models/horizon-guard-small")
result = check_injection(text, classifier=classifier)
result.layers["classifier"]       # "ran"
result.classifier                 # name, revision, probability, threshold
```

| Variable | Meaning |
| --- | --- |
| `VECSHIELD_INJECTION_MODEL_DIR` | Directory holding the model file and `tokenizer.json`. |
| `VECSHIELD_INJECTION_MODEL` | Which catalogued model it is, if the directory is ambiguous. |
| `VECSHIELD_INJECTION_MODEL_THRESHOLD` | Override the probability at which the classifier flags. |

## Which models

The scanner loads a model only if the SHA-256 of both files matches its
catalogue (`vecshield.injection.CLASSIFIER_CATALOG`). A file that does not
match is refused. Both catalogued models are Apache-2.0, not gated, and load as
data: one ONNX graph, one tokenizer JSON, no repository code.

| Name | Repository | Revision | File to place in the directory |
| --- | --- | --- | --- |
| `horizon-guard-small` | `Horizon-Labs/prompt-injection-guard-small` | `2efc2ed5` | `onnx/model_quantized.onnx` as `model_quantized.onnx`, and `tokenizer.json` |
| `wolf-defender-small` | `patronus-studio/wolf-defender-prompt-injection-small` | `2484cc9a` | `onnx/onnx_mixed/model_mixed.onnx` as `model_mixed.onnx`, and `onnx/onnx_mixed/tokenizer.json` |

Download them from Hugging Face at the listed revision, on a machine that is
allowed to, and copy the directory to where the scanner runs. The server never
fetches a model in response to a request.

Wolf's card notes that its `onnx_mixed` file can return near-random scores on
x86 CPUs without VNNI and offers an `_x86` variant. That variant has a
different hash and is not in the catalogue; it was not measured here.

Models that are not catalogued are not loaded by name. Meta's Prompt Guard 2 is
under a licence that does not fit this project's distribution, and PIGuard
needs `trust_remote_code`.

## What it costs, and what it was measured to do

The [injection benchmark](benchmarks/injection.md) has the figures and their
caveats. In short, on 20,508 rows of public data:

| | Rules alone | Rules + Horizon small | Rules + Wolf small |
|---|---|---|---|
| Developed-against sources (test split): F1 / ROC-AUC | 0.55 / 0.74 | 0.84 / 0.98 | 0.91 / 0.97 |
| Held-out sources: F1 / ROC-AUC | 0.21 / 0.56 | 0.66 / 0.95 | 0.73 / 0.95 |
| Held-out sources: false-positive rate | 0.12% | 0.19% | 0.61% |
| Held-out sources outside Horizon's listed training data: recall | 2% | 24% | 48% |

Horizon is the more conservative of the two and its card says more about its
training data; Wolf finds more and flags more ordinary text. Each model's
default threshold (0.925 and 0.87) was set on the benchmark's dev split for a
false-positive rate of one in a thousand there.

- It is roughly 35 times slower than the rules on a CPU: about 55
  milliseconds per thousand characters.
- Each model's card lists the public datasets it was trained on, and several
  are in the benchmark. Scores on those sources are not out-of-sample and the
  write-up marks them.
- Published adaptive attacks defeat classifiers like these. It raises the cost
  of a planted instruction; it is not a boundary.
