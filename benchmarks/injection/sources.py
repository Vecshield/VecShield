"""Pinned third-party sources for the prompt-injection benchmark.

Nothing here is vendored. Each source is fetched by ``fetch.py`` at the pinned
revision, and every file's SHA-256 is checked against ``sources.lock.json``.
The hashes there were recorded on first download (2026-11-18) from the
revisions named here; they establish that a later run reads the same bytes,
not that the upstream publisher is trustworthy. GitHub tarballs are pinned by
commit only: GitHub does not promise byte-identical archives over time.

``role`` says how a source may be used:

``attack``   payloads or attack-bearing documents
``benign``   documents with no injected instruction
``mixed``    labelled rows of both kinds

``split`` says where its rows may appear:

``dev+test`` rows are divided deterministically; rules may be developed
             against the dev half only, and the test half is what is reported
``heldout``  never looked at while developing rules; reported only
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    id: str
    kind: str                 # "hf" | "github_raw" | "github_tarball" | "hf_rows"
    repo: str
    revision: str
    licence: str
    role: str
    split: str
    files: tuple[str, ...] = ()
    note: str = ""
    url: str = ""


SOURCES: tuple[Source, ...] = (
    # ---- attacks ---------------------------------------------------------- #
    Source(
        id="bipia", kind="github_raw", repo="microsoft/BIPIA",
        revision="a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
        licence="MIT", role="mixed", split="dev+test",
        url="https://github.com/microsoft/BIPIA",
        note=("Indirect-injection attack strings (text and code) and the email, "
              "table and code contexts they are placed in. The WebQA and "
              "summarisation contexts are not redistributable and are not used. "
              "The benchmark's own train/test attack files are our dev/test."),
        files=("benchmark/text_attack_train.json", "benchmark/text_attack_test.json", "benchmark/code_attack_train.json", "benchmark/code_attack_test.json", "benchmark/email/train.jsonl", "benchmark/email/test.jsonl", "benchmark/table/train.jsonl", "benchmark/table/test.jsonl", "benchmark/code/train.jsonl", "benchmark/code/test.jsonl")),
    Source(
        id="deepset", kind="hf", repo="deepset/prompt-injections",
        revision="4f61ecb038e9c3fb77e21034b22511b523772cdd",
        licence="Apache-2.0", role="mixed", split="dev+test",
        url="https://huggingface.co/datasets/deepset/prompt-injections",
        note="Short prompts, English and German, labelled injection or not.",
        files=("data/train-00000-of-00001-9564e8b05b4757ab.parquet", "data/test-00000-of-00001-701d16158af87368.parquet")),
    Source(
        id="yanismiraoui", kind="hf", repo="yanismiraoui/prompt_injections",
        revision="b1e3ba53e3290512e7a37c25a90e10c1b4cfd166",
        licence="Apache-2.0", role="attack", split="dev+test",
        url="https://huggingface.co/datasets/yanismiraoui/prompt_injections",
        note="Short injection prompts in several European languages.",
        files=("prompt_injections.csv",)),
    Source(
        id="gandalf", kind="hf", repo="Lakera/gandalf_ignore_instructions",
        revision="04737b65e90a6794ec227012e4a255a7def6344b",
        licence="MIT", role="attack", split="dev+test",
        url="https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
        note="Human-written direct injections from the Gandalf game.",
        files=("data/train-00000-of-00001-ded53be747ff55cd.parquet", "data/validation-00000-of-00001-94481a2a09ff2fff.parquet", "data/test-00000-of-00001-bc92128b9288a6d1.parquet")),
    Source(
        id="injecagent", kind="github_raw", repo="uiuc-kang-lab/InjecAgent",
        revision="f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
        licence="MIT", role="attack", split="dev+test",
        url="https://github.com/uiuc-kang-lab/InjecAgent",
        note=("Attacker instructions placed inside simulated tool responses "
              "(JSON documents). Held out in the first round of this benchmark "
              "(dataset 78ed55b9); split dev/test from the second round on."),
        files=("data/test_cases_dh_base.json", "data/test_cases_ds_base.json", "data/test_cases_dh_enhanced.json", "data/test_cases_ds_enhanced.json")),
    Source(
        id="llmail", kind="hf", repo="microsoft/llmail-inject-challenge",
        revision="1063bdf01ec8762b812d5e06ee768a06faa5a6f7",
        licence="MIT", role="mixed", split="dev+test",
        url="https://huggingface.co/datasets/microsoft/llmail-inject-challenge",
        note=("Emails submitted by participants in a public challenge to attack "
              "an email assistant that had injection defences in place, plus "
              "the organisers' benign emails for false-positive tests. Phase 2 "
              "only. Held out in the first round of this benchmark (dataset "
              "78ed55b9); split dev/test from the second round on."),
        files=("data/labelled_unique_submissions_phase2.json", "data/emails_for_fp_tests.json")),
    Source(
        id="agentdojo", kind="github_raw", repo="ethz-spylab/agentdojo",
        revision="089ed468cf3ed0322acc66b0211f26d9d90dbf60",
        licence="MIT", role="mixed", split="dev+test",
        url="https://github.com/ethz-spylab/agentdojo",
        note=("Agent benchmark. Its tool-output documents (emails, files, "
              "calendar entries, web pages) with its attacker goals placed in "
              "them by its own attack templates, rebuilt here from the data "
              "files and from string constants read out of the source with "
              "`ast`; no AgentDojo code is run."),
        files=(
            "src/agentdojo/attacks/baseline_attacks.py",
            "src/agentdojo/attacks/important_instructions_attacks.py",
            "src/agentdojo/data/suites/banking/environment.yaml",
            "src/agentdojo/data/suites/banking/injection_vectors.yaml",
            "src/agentdojo/data/suites/slack/environment.yaml",
            "src/agentdojo/data/suites/slack/injection_vectors.yaml",
            "src/agentdojo/data/suites/travel/environment.yaml",
            "src/agentdojo/data/suites/travel/injection_vectors.yaml",
            "src/agentdojo/data/suites/workspace/include/calendar.yaml",
            "src/agentdojo/data/suites/workspace/include/cloud_drive.yaml",
            "src/agentdojo/data/suites/workspace/include/inbox.yaml",
            "src/agentdojo/data/suites/workspace/injection_vectors.yaml",
            "src/agentdojo/default_suites/v1/banking/injection_tasks.py",
            "src/agentdojo/default_suites/v1/slack/injection_tasks.py",
            "src/agentdojo/default_suites/v1/travel/injection_tasks.py",
            "src/agentdojo/default_suites/v1/workspace/injection_tasks.py",
        )),
    # ---- attacks, held out from the second round on ------------------------ #
    Source(
        id="gandalf_summarization", kind="hf", repo="Lakera/gandalf_summarization",
        revision="8e213cc8dd65f099c61dc32dbcfdb2ff6b1c92d8", licence="MIT", role="attack", split="heldout",
        url="https://huggingface.co/datasets/Lakera/gandalf_summarization",
        note=("Human-written text submitted to a summarisation level of the "
              "Gandalf game: the instruction is inside a document to be "
              "summarised. Held out."),
        files=("data/train-00000-of-00001-44378fdb62cbf9b7.parquet",
               "data/validation-00000-of-00001-c7b174a69fca3472.parquet",
               "data/test-00000-of-00001-1696577a5023b698.parquet")),
    Source(
        id="slabs", kind="hf", repo="S-Labs/prompt-injection-dataset",
        revision="002a9dd18514abd021869823d6b0429b38606d99", licence="MIT", role="mixed", split="heldout",
        url="https://huggingface.co/datasets/S-Labs/prompt-injection-dataset",
        note="Labelled prompts, injection or not. Held out.",
        files=("data/train.csv", "data/validation.csv", "data/test.csv")),
    Source(
        id="wambosec", kind="hf", repo="wambosec/prompt-injections",
        revision="071ee17a60112b7f9f808398156b430aadfaf1d2", licence="MIT", role="mixed", split="heldout",
        url="https://huggingface.co/datasets/wambosec/prompt-injections",
        note="Labelled prompts, injection or not. Held out.",
        files=("data/train-00000-of-00001.parquet", "data/test-00000-of-00001.parquet")),
    Source(
        id="turkish", kind="hf", repo="beratcmn/turkish-prompt-injections",
        revision="c40c38f8ca632052fbfec19e90fab31fce33eda1", licence="Apache-2.0", role="mixed", split="heldout",
        url="https://huggingface.co/datasets/beratcmn/turkish-prompt-injections",
        note=("Turkish prompts. The scanner has no rules for Turkish; this "
              "measures a language it was not written for. Held out."),
        files=("data/train.jsonl", "data/test.jsonl")),
    Source(
        id="spml", kind="hf", repo="reshabhs/SPML_Chatbot_Prompt_Injection",
        revision="02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5", licence="MIT", role="mixed", split="heldout",
        url="https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection",
        note=("User prompts written against chatbots with a stated system "
              "prompt, labelled as injection or not. Only the user prompt is "
              "scored. Held out."),
        files=("spml_prompt_injection.csv",)),
    Source(
        id="jailbreak", kind="hf", repo="jackhhao/jailbreak-classification",
        revision="2f2ceeb39658696fd3f462403562b6eea5306287", licence="Apache-2.0", role="mixed", split="heldout",
        url="https://huggingface.co/datasets/jackhhao/jailbreak-classification",
        note=("Long role-play jailbreak prompts and benign prompts. Jailbreaks "
              "aimed at a chatbot are outside what the scanner is for; reported "
              "apart. Held out."),
        files=("default/jailbreak_dataset_full.csv",)),
    # ---- benign ----------------------------------------------------------- #
    Source(
        id="notinject", kind="hf", repo="leolee99/NotInject",
        revision="847ae76cf8fea5ed325429e569ae8cfef022d2e0",
        licence="MIT", role="benign", split="heldout",
        url="https://huggingface.co/datasets/leolee99/NotInject",
        note=("339 benign sentences containing words injection detectors "
              "over-trigger on. Held out, as its authors ask."),
        files=("data/NotInject_one-00000-of-00001.parquet", "data/NotInject_two-00000-of-00001.parquet", "data/NotInject_three-00000-of-00001.parquet")),
    Source(
        id="runbooks_openshift", kind="github_tarball", repo="openshift/runbooks",
        revision="bc71a1798c469150156e95ade3d57ba3684c9c4d",
        licence="Apache-2.0", role="benign", split="dev+test",
        url="https://github.com/openshift/runbooks",
        note="Alert runbooks: imperative operational prose."),
    Source(
        id="runbooks_prometheus", kind="github_tarball", repo="prometheus-operator/runbooks",
        revision="a685d14cf5128bb30e2bf935c3983decd772d885",
        licence="Apache-2.0", role="benign", split="dev+test",
        url="https://github.com/prometheus-operator/runbooks",
        note="Alert runbooks: imperative operational prose."),
    Source(
        id="django_docs", kind="github_tarball", repo="django/django",
        revision="9e2e5a31e2ef2e8673d3c2a38d2a391dbf42cf23",
        licence="BSD-3-Clause", role="benign", split="dev+test",
        url="https://github.com/django/django",
        note="Framework documentation (docs/ only): API reference and how-to text."),
    Source(
        id="owasp_cheatsheets", kind="github_tarball", repo="OWASP/CheatSheetSeries",
        revision="c12dd22e17cefa0b8448f3a82b15a60bb3357914",
        licence="CC-BY-SA-4.0", role="benign", split="dev+test",
        url="https://github.com/OWASP/CheatSheetSeries",
        note=("Security guidance (cheatsheets/ only), including pages that "
              "describe and quote injection attacks. Evaluation only; "
              "share-alike text is never used to build shipped data."),
    ),
    Source(
        id="prompt_guide", kind="github_tarball", repo="dair-ai/Prompt-Engineering-Guide",
        revision="57673726396dd94acb23bdb1e67f27c78ee85a8e",
        licence="MIT", role="benign", split="dev+test",
        url="https://github.com/dair-ai/Prompt-Engineering-Guide",
        note=("Prompt-engineering guide (English pages): text about prompts, "
              "system messages and adversarial prompting, with quoted examples."),
    ),
    Source(
        id="tldr_pages", kind="github_tarball", repo="tldr-pages/tldr",
        revision="bc614bf4855805510fadd5ba3823f1e556f8ca63",
        licence="CC-BY-4.0", role="benign", split="dev+test",
        url="https://github.com/tldr-pages/tldr",
        note=("Command-line help pages (English): terse imperatives full of "
              "words like ignore, override, bypass and force. Evaluation only."),
    ),
    Source(
        id="cursor_rules", kind="github_tarball", repo="PatrickJS/awesome-cursorrules",
        revision="b044f956f021b6e8877f16781bcfc466a6a120e9",
        licence="CC0-1.0", role="benign", split="heldout",
        url="https://github.com/PatrickJS/awesome-cursorrules",
        note=("Rule files written for AI coding assistants: legitimate "
              "instructions addressed to a model. The hardest benign class "
              "for a detector of instructions addressed to a model. Held out."),
    ),
    Source(
        id="wikipedia", kind="hf_rows", repo="wikimedia/wikipedia",
        revision="20231101", licence="CC-BY-SA-4.0", role="benign", split="dev+test",
        url="https://huggingface.co/datasets/wikimedia/wikipedia",
        note=("Encyclopedia articles from the 2023-11-01 dumps in English, German, "
              "French, Spanish, Russian, Chinese, Japanese, Arabic, Persian and "
              "Hebrew, read through the dataset viewer's rows API at fixed "
              "offsets. Evaluation only."),
    ),
)

BY_ID = {s.id: s for s in SOURCES}

#: Wikipedia configs and how many 100-row pages to read from each. Offsets are
#: spread through the dump (page * WIKI_STRIDE) so the sample is not the first
#: articles ever written.
WIKI_PAGES = {"en": 14, "de": 3, "fr": 3, "es": 3, "ru": 3, "zh": 3, "ja": 3,
              "ar": 3, "fa": 3, "he": 3}
WIKI_STRIDE = 9_973
