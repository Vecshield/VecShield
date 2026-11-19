# Prompt-injection benchmark

Measures the injection scanner (`vecshield.injection`) on public data, in the
form it meets in a vector store: document-shaped text with an instruction
somewhere in it, beside a much larger body of ordinary documents.

Results and their limits are written up in
[`docs/library/benchmarks/injection.md`](../../docs/library/benchmarks/injection.md)
(second round) and
[`injection_round1.md`](../../docs/library/benchmarks/injection_round1.md)
(first round). The numbers there come from the files in [`recorded/`](recorded/).

## What it does

1. **Fetch** (`fetch.py`) downloads each source in [`sources.py`](sources.py)
   at a pinned revision and checks every file against
   [`sources.lock.json`](sources.lock.json). Nothing is vendored.
2. **Build** (`build.py`) assembles one dataset, deterministically: attack
   strings as published; the same strings placed inside benign documents at
   the start, middle and end and at three document lengths; under 22
   obfuscations and ten stacked pairs ([`mutate.py`](mutate.py)); inside
   structured containers, split across paragraphs, in 30,000-character
   documents and in documents in another language; BIPIA attacks in BIPIA's
   own contexts; AgentDojo's tool outputs with its goals placed by its attack
   templates ([`agentdojo.py`](agentdojo.py), which reads its data and source
   constants and runs none of its code); and benign text from runbooks,
   framework documentation, command-line help, security guidance, a
   prompt-engineering guide, rule files for AI assistants and Wikipedia in ten
   languages. The dataset's SHA-256 is written to a manifest.
3. **Run** (`run.py`) scores detectors and writes a summary per detector: F1,
   precision, recall, false-positive rate, ROC-AUC and PR-AUC with intervals,
   and F1 at thresholds chosen on the dev split.
4. **Fuse** (`fuse.py`) combines the scanner's stored scores with a
   classifier's, by the library's own rule, at a threshold taken from dev.
5. **Report** (`report.py`) prints the tables and, with `--record`, copies the
   summaries into `recorded/`.

## Splits

| Split | What | Use |
|---|---|---|
| `dev` | Half of each `dev+test` source, by hash | Rules may be developed against it |
| `test` | The other half | Reported; not read while developing rules |
| `heldout` | Whole sources (see the table below) | Reported; never read while developing rules |

BIPIA, deepset and Gandalf ship their own train/test files, which are used as
dev/test. The rest are split by a hash of the row or document; AgentDojo and
InjecAgent are split by attacker goal, so a goal seen in dev is never in test.

In the first round (dataset `78ed55b9`) InjecAgent and LLMail-Inject were held
out. From the second round (dataset `4bbe1ae7`) they are split dev/test, and
the sources marked "held out" below take their place.

## Run it

```bash
pip install -e . -r benchmarks/injection/requirements.txt
python benchmarks/injection/fetch.py            # ~270 MB, verifies hashes
python benchmarks/injection/build.py
python benchmarks/injection/run.py --detectors legacy vecshield
python benchmarks/injection/report.py
```

`legacy` is the scanner as it stood at commit `0041576`, loaded from git and
called as the integrity engine called it then (first 5,000 characters).

Classifiers are optional and need a local copy of the model files
(`detectors.CLASSIFIERS` lists the ones scored, and which of this benchmark's
sources each was trained on):

```bash
pip install onnxruntime tokenizers
python benchmarks/injection/run.py --detectors horizon_small --model-dir /path/to/model \
    --sample 200 --all-negatives --splits dev --tag dev --canonical-input
python benchmarks/injection/run.py --detectors horizon_small --model-dir /path/to/model \
    --sample 150 --all-negatives --splits test heldout --tag final --canonical-input
python benchmarks/injection/fuse.py --classifier horizon_small --scanner-tag final \
    --classifier-tag final --threshold-tag dev --out-tag fused
```

A full model pass over the sampled rows takes about half an hour on a laptop
CPU.

## Sources and licences

See [`sources.py`](sources.py) for the revision and note on each.

| Source | Licence | Role | Split |
|---|---|---|---|
| [BIPIA](https://github.com/microsoft/BIPIA) | MIT | attacks and contexts | dev+test |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | labelled prompts | dev+test |
| [yanismiraoui/prompt_injections](https://huggingface.co/datasets/yanismiraoui/prompt_injections) | Apache-2.0 | attacks, several languages | dev+test |
| [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT | attacks | dev+test |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | MIT | attacks in tool output | dev+test (held out in round one) |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | MIT | attack emails, benign emails | dev+test (held out in round one) |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | MIT | attacks in tool output, clean tool output | dev+test |
| [Gandalf summarisation](https://huggingface.co/datasets/Lakera/gandalf_summarization) | MIT | instructions inside text to summarise | held out |
| [S-Labs](https://huggingface.co/datasets/S-Labs/prompt-injection-dataset), [wambosec](https://huggingface.co/datasets/wambosec/prompt-injections) | MIT | labelled prompts | held out |
| [SPML](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection) | MIT | labelled user prompts (rows taken from Gandalf excluded) | held out |
| [Turkish prompt injections](https://huggingface.co/datasets/beratcmn/turkish-prompt-injections) | Apache-2.0 | labelled prompts, Turkish | held out |
| [jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | Apache-2.0 | jailbreaks (reported apart), benign prompts | held out |
| [NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | benign, trigger words | held out |
| [awesome-cursorrules](https://github.com/PatrickJS/awesome-cursorrules) | CC0-1.0 | benign instructions addressed to a model | held out |
| [tldr-pages](https://github.com/tldr-pages/tldr) | CC BY 4.0 | benign, command-line imperatives | dev+test |
| [openshift/runbooks](https://github.com/openshift/runbooks), [prometheus-operator/runbooks](https://github.com/prometheus-operator/runbooks) | Apache-2.0 | benign | dev+test |
| [django/django](https://github.com/django/django) `docs/` | BSD-3-Clause | benign | dev+test |
| [OWASP CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) | CC BY-SA 4.0 | benign, discusses attacks | dev+test |
| [Prompt-Engineering-Guide](https://github.com/dair-ai/Prompt-Engineering-Guide) | MIT | benign, quotes attacks | dev+test |
| [wikimedia/wikipedia](https://huggingface.co/datasets/wikimedia/wikipedia) 2023-11-01 | CC BY-SA 4.0 | benign, ten languages | dev+test |

Attribution and share-alike text is used only as benign evaluation documents and is never
copied into the repository or into anything shipped. Publishing figures
computed from these sources is fine; redistributing the sources is not what
this harness does.

The downloaded trees contain files written for AI coding agents (`AGENTS.md`,
`CLAUDE.md`). The harness reads only the documentation paths named in
`build.py`, and nothing it downloads is executed or imported.

## Layout

```
benchmarks/injection/
  sources.py          pinned sources, licences, roles
  sources.lock.json   SHA-256 of every pinned file
  fetch.py            download and verify
  mutate.py           the 22 obfuscations
  agentdojo.py        AgentDojo's injected tool outputs, rebuilt from its data
  build.py            deterministic dataset assembly
  detectors.py        legacy scanner, current scanner, classifier adapters
  metrics.py          Wilson intervals, F1, ROC-AUC, PR-AUC, thresholds from dev
  run.py              score detectors, write summaries
  fuse.py             scanner and classifier combined, from stored scores
  report.py           tables; --record copies summaries to recorded/
  recorded/           the summaries the write-up quotes
  .cache/             downloads and the built dataset (git-ignored)
  results/            per-run outputs (git-ignored)
```
