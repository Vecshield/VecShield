# Prompt-injection detection on public data

Second round, measured 2026-11-18. Harness:
[`benchmarks/injection/`](../../../benchmarks/injection/). Recorded summaries:
the `2026-11-18-round2-*` files in
[`benchmarks/injection/recorded/`](../../../benchmarks/injection/recorded/).
The first round is kept as written in [injection_round1.md](injection_round1.md).

This page reports how the injection scanner performs on public attack data and
on ordinary text: the signature rules alone, and the rules with an optional
pre-trained classifier beside them. It gives F1, ROC-AUC and PR-AUC as well as
recall and false-positive rate, on twice the data of the first round and on
harder constructed cases, and it says what the figures do not show.

## Summary

Rules alone, every row:

| | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.3 |
|---|---|---|---|
| Test split: F1 | 0.269 | 0.438 | **0.575** |
| Test split: ROC-AUC | 0.595 | 0.659 | **0.801** |
| Test split: recall / false-positive rate | 0.155 / 0.20% | 0.281 / 0.26% | 0.404 / 0.25% |
| Held-out sources: F1 | 0.202 | 0.286 | 0.278 |
| Held-out sources: ROC-AUC | 0.553 | 0.583 | 0.585 |
| Held-out sources: recall / false-positive rate | 0.115 / 1.88% | 0.172 / 1.93% | 0.161 / 0.12% |

With a pre-trained classifier beside the rules, on a sample of the same rows
(every benign row, up to 150 attack rows per family and source):

| | Rules alone | Rules + Horizon small | Rules + Wolf small |
|---|---|---|---|
| Test split: F1 | 0.551 | 0.839 | **0.913** |
| Test split: ROC-AUC | 0.737 | **0.977** | 0.973 |
| Test split: recall / false-positive rate | 0.383 / 0.25% | 0.728 / 0.28% | 0.847 / 0.31% |
| Held-out sources: F1 | 0.208 | 0.656 | **0.734** |
| Held-out sources: ROC-AUC | 0.557 | 0.946 | **0.953** |
| Held-out sources: recall / false-positive rate | 0.118 / 0.12% | 0.499 / 0.19% | 0.620 / 0.61% |

What to take from this:

1. **The rules got better where they were developed and did not get better
   anywhere else.** On the test split, F1 rose from 0.44 to 0.58 and ROC-AUC
   from 0.66 to 0.80. On six sources the rules had never been run against,
   F1 and ROC-AUC did not move (0.29 to 0.28, 0.58 to 0.59). This is the same
   result as the first round, on different held-out data. Signature rules do
   not generalise to attack styles they were not written for.
2. **On truly fresh attack data the rules are no better than chance at
   ranking.** On the held-out sources that the Horizon model's card does not
   list as training data (SPML, Turkish prompts, Gandalf summarisation), the
   rules find 10 of 440 attacks and their ROC-AUC is 0.49.
3. **A pre-trained classifier is where F1 and AUC actually improve.** Beside
   the rules it brings test F1 to 0.84–0.91 and ROC-AUC to 0.97, and held-out
   F1 to 0.66–0.73 and ROC-AUC to 0.95, at false-positive rates of 0.2% to
   0.6%.
4. **Much of that gain is on data the models were trained on.** Both model
   cards name several of this benchmark's sources as training data. On the
   held-out sources outside Horizon's listed training data, Horizon finds 24%
   of attacks and Wolf 48%. Those are the figures to plan with.
5. **One rule was changed after seeing held-out results, and this page says
   so.** In the frozen pack (2026.11.2) a single rule, plain "pretend to be",
   fired on 149 of the 158 held-out false positives, nearly all of them benign
   role-play prompts. It was made a supporting signal in 2026.11.3. Figures for both
   packs are given; the 2026.11.2 held-out figures are the unbiased ones.

## How to read the numbers

- **F1** and **precision** depend on the mix of attack and benign rows, which
  here is roughly even and in a real store is not: attacks are rare. They
  compare detectors on the same rows. They are not the precision to expect in
  the field. **False-positive rate** and **ROC-AUC** do not depend on the mix.
- **ROC-AUC** is the probability that a random attack row scores above a
  random benign row, ties counting half. **PR-AUC** is average precision.
  Both come with a 95% bootstrap interval (200 resamples within each class).
- **Recall** and **false-positive rate** are given as
  `value [95% Wilson interval] (count/total)` at each detector's own threshold.
- **Thresholds chosen on dev** are picked on the dev split and applied to the
  other splits unchanged. An F1 at a threshold tuned on the rows it is scored
  on is not reported anywhere on this page.
- A rate over fewer than five rows is not reported.
- Jailbreak prompts aimed at a chatbot are scored and reported in their own
  table, and left out of the headline figures. That was decided before any
  second-round result was seen: the scanner is for instructions planted in
  stored content.

## What was measured

Dataset SHA-256 `4bbe1ae77ab3de03d115b3278b954b0f6a7eb3f3b3fda38824101296e4a1acdb`, 54,192 rows, built deterministically from
pinned sources
([list and licences](../../../benchmarks/injection/README.md#sources-and-licences)).

| Split | Attack rows | Benign rows | What it is |
|---|---|---|---|
| dev | 11,719 | 8,183 | Half of each developed-against source. Rules were written against it, and the classifier thresholds were set on it. |
| test | 10,610 | 8,105 | The other half. Not read while writing rules. |
| held-out | 7,015 | 8,560 | Whole sources first read by this harness in this round, never read while writing rules. |

Changes from the first round:

- **Promoted to dev/test:** InjecAgent and LLMail-Inject, which were held out
  in the first round. Their dev halves were read to write rules.
- **New in dev/test:** AgentDojo's tool-output documents with its attacker
  goals placed by its five attack templates (rebuilt from its data files
  without running its code), and 3,000 command-line help pages as benign text.
- **New held-out sources:** Gandalf summarisation (instructions inside a
  document to be summarised), S-Labs, wambosec and SPML (labelled prompts),
  Turkish prompts (a language with no rules), rule files written for AI coding
  assistants (benign instructions addressed to a model), and a jailbreak set.
  NotInject stays held out.
- **Harder constructed cases**, built mechanically from the public payloads:
  a payload inside a structured container (a JSON field, a CSV cell, a
  Markdown table, a code comment, YAML front matter, a quoted email, an image
  `alt`, a footnote); a payload split across two paragraphs with ordinary text
  between; one payload in a 30,000-character document; a payload in a document
  in another language; and ten pairs of stacked disguises.

## How the work was done, and what that does to these numbers

1. The dataset was rebuilt and rule pack 2026.11.1 was scored on all of it
   before anything was changed. Only its dev figures were looked at.
2. Rules were then developed against the **dev split only**, in one round:
   decoding made compositional, eleven rules added, two narrowed, and unflagged
   text given a graded score. The file formats of the new held-out sources
   were learned from column names and label counts; no held-out text was
   printed. The dev halves of InjecAgent, LLMail-Inject and AgentDojo were
   read.
3. Two pre-trained classifiers were scored on a dev sample and each one's
   threshold was set there, for a false-positive rate of 0.1% on the dev
   split's benign rows (0.925 for Horizon, 0.87 for Wolf).
4. Pack 2026.11.2 and both thresholds were frozen, and the test and held-out
   splits were scored once. Those are the "frozen" figures.
5. The held-out result showed one rule responsible for nine in ten false
   positives. It was demoted (pack 2026.11.3) and the scanner re-scored. **The
   2026.11.3 held-out figures have therefore seen the held-out data once**, for
   that one rule. The change cannot raise recall, and it lowered held-out
   recall slightly (0.171 to 0.161). Test figures are identical for both packs.

What follows from that:

- **The test split overstates what to expect elsewhere**, more than in the
  first round. LLMail-Inject is 43% of its attack rows, and every LLMail attack
  has the same goal (send an email to one address), so rules written from its
  dev half fit its test half closely. AgentDojo has five templates, all seen.
- **The held-out split is the estimate to use for the rules.**
- **The classifiers' figures need their own caveat**, in the next section but
  one: several of this benchmark's sources are in their training data.

## Rules alone

### Test split

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Scanner before this work | 0.269 | 0.990 | 0.155 [0.149, 0.162] (1649/10610) | 0.002 [0.001, 0.003] (16/8105) | 0.595 [0.590, 0.601] | 0.657 [0.654, 0.662] |
| Rule pack 2026.11.1 | 0.438 | 0.993 | 0.281 [0.273, 0.290] (2984/10610) | 0.003 [0.002, 0.004] (21/8105) | 0.659 [0.654, 0.664] | 0.713 [0.709, 0.717] |
| Rule pack 2026.11.2 (frozen) | 0.575 | 0.995 | 0.404 [0.395, 0.413] (4285/10610) | 0.003 [0.002, 0.004] (20/8105) | 0.801 [0.796, 0.805] | 0.829 [0.825, 0.833] |
| Rule pack 2026.11.3 | 0.575 | 0.995 | 0.404 [0.395, 0.413] (4285/10610) | 0.003 [0.002, 0.004] (20/8105) | 0.801 [0.796, 0.805] | 0.829 [0.825, 0.833] |

Thresholds chosen on the dev split, applied here unchanged:

| Detector | Threshold from dev for FPR ≤ 1% | Recall | FPR here | F1 | Threshold from dev for FPR ≤ 0.1% | Recall | FPR here | F1 |
|---|---|---|---|---|---|---|---|---|
| Scanner before this work | 0.4000 | 0.177 | 0.0043 | 0.299 | 0.5000 | 0.155 | 0.0020 | 0.269 |
| Rule pack 2026.11.1 | 0.4000 | 0.299 | 0.0048 | 0.460 | 0.6000 | 0.238 | 0.0015 | 0.384 |
| Rule pack 2026.11.3 | 0.3500 | 0.490 | 0.0062 | 0.655 | 0.6000 | 0.361 | 0.0015 | 0.531 |

| Family / source | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.3 |
|---|---|---|---|
| `agentdojo_direct/agentdojo` | 0.000 [0.000, 0.066] (0/54) | 0.000 [0.000, 0.066] (0/54) | 0.000 [0.000, 0.066] (0/54) |
| `agentdojo_ignore_previous/agentdojo` | 0.000 [0.000, 0.066] (0/54) | 0.000 [0.000, 0.066] (0/54) | 0.926 [0.825, 0.971] (50/54) |
| `agentdojo_important_instructions/agentdojo` | 0.000 [0.000, 0.066] (0/54) | 0.000 [0.000, 0.066] (0/54) | 1.000 [0.934, 1.000] (54/54) |
| `agentdojo_injecagent/agentdojo` | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) |
| `agentdojo_system_message/agentdojo` | 0.000 [0.000, 0.066] (0/54) | 0.000 [0.000, 0.066] (0/54) | 1.000 [0.934, 1.000] (54/54) |
| `bipia_code/bipia` | 0.000 [0.000, 0.025] (0/150) | 0.060 [0.032, 0.110] (9/150) | 0.060 [0.032, 0.110] (9/150) |
| `bipia_text/bipia` | 0.000 [0.000, 0.017] (0/224) | 0.147 [0.107, 0.200] (33/224) | 0.147 [0.107, 0.200] (33/224) |
| `container_payload/deepset` | 0.083 [0.023, 0.259] (2/24) | 0.125 [0.043, 0.310] (3/24) | 0.125 [0.043, 0.310] (3/24) |
| `container_payload/gandalf` | 0.540 [0.384, 0.690] (20/37) | 0.676 [0.515, 0.804] (25/37) | 0.676 [0.515, 0.804] (25/37) |
| `container_payload/yanismiraoui` | 0.011 [0.003, 0.040] (2/179) | 0.196 [0.144, 0.260] (35/179) | 0.196 [0.144, 0.260] (35/179) |
| `diluted_payload/deepset` | 0.042 [0.007, 0.202] (1/24) | 0.125 [0.043, 0.310] (3/24) | 0.125 [0.043, 0.310] (3/24) |
| `diluted_payload/gandalf` | 0.162 [0.076, 0.311] (6/37) | 0.676 [0.515, 0.804] (25/37) | 0.676 [0.515, 0.804] (25/37) |
| `diluted_payload/yanismiraoui` | 0.006 [0.001, 0.031] (1/179) | 0.196 [0.144, 0.260] (35/179) | 0.196 [0.144, 0.260] (35/179) |
| `direct_prompt/deepset` | 0.067 [0.026, 0.159] (4/60) | 0.167 [0.093, 0.280] (10/60) | 0.167 [0.093, 0.280] (10/60) |
| `direct_prompt/gandalf` | 0.411 [0.324, 0.503] (46/112) | 0.616 [0.524, 0.701] (69/112) | 0.616 [0.524, 0.701] (69/112) |
| `direct_prompt/yanismiraoui` | 0.006 [0.002, 0.017] (3/509) | 0.214 [0.181, 0.252] (109/509) | 0.214 [0.181, 0.252] (109/509) |
| `embedded_payload/deepset` | 0.067 [0.026, 0.159] (4/60) | 0.167 [0.093, 0.280] (10/60) | 0.167 [0.093, 0.280] (10/60) |
| `embedded_payload/gandalf` | 0.339 [0.258, 0.431] (38/112) | 0.616 [0.524, 0.701] (69/112) | 0.616 [0.524, 0.701] (69/112) |
| `embedded_payload/yanismiraoui` | 0.004 [0.001, 0.013] (2/542) | 0.216 [0.183, 0.252] (117/542) | 0.216 [0.183, 0.252] (117/542) |
| `evasion/gandalf` | 0.294 [0.271, 0.319] (405/1377) | 0.689 [0.664, 0.713] (949/1377) | 0.689 [0.664, 0.713] (949/1377) |
| `foreign_carrier_payload/deepset` | 0.083 [0.023, 0.259] (2/24) | 0.125 [0.043, 0.310] (3/24) | 0.125 [0.043, 0.310] (3/24) |
| `foreign_carrier_payload/gandalf` | 0.540 [0.384, 0.690] (20/37) | 0.676 [0.515, 0.804] (25/37) | 0.676 [0.515, 0.804] (25/37) |
| `foreign_carrier_payload/yanismiraoui` | 0.012 [0.003, 0.042] (2/168) | 0.202 [0.149, 0.270] (34/168) | 0.202 [0.149, 0.270] (34/168) |
| `injecagent_base/injecagent` | 0.000 [0.000, 0.007] (0/527) | 0.000 [0.000, 0.007] (0/527) | 0.000 [0.000, 0.007] (0/527) |
| `injecagent_enhanced/injecagent` | 1.000 [0.993, 1.000] (527/527) | 1.000 [0.993, 1.000] (527/527) | 1.000 [0.993, 1.000] (527/527) |
| `llmail_attempt/llmail` | 0.092 [0.082, 0.102] (275/3003) | 0.103 [0.092, 0.114] (308/3003) | 0.287 [0.272, 0.304] (863/3003) |
| `llmail_succeeded/llmail` | 0.097 [0.083, 0.112] (156/1610) | 0.151 [0.134, 0.169] (243/1610) | 0.419 [0.395, 0.444] (675/1610) |
| `split_payload/deepset` | 0.083 [0.023, 0.259] (2/24) | 0.125 [0.043, 0.310] (3/24) | 0.125 [0.043, 0.310] (3/24) |
| `split_payload/gandalf` | 0.469 [0.309, 0.635] (15/32) | 0.562 [0.393, 0.718] (18/32) | 0.562 [0.393, 0.718] (18/32) |
| `split_payload/yanismiraoui` | 0.000 [0.000, 0.023] (0/163) | 0.178 [0.127, 0.244] (29/163) | 0.178 [0.127, 0.244] (29/163) |
| `stacked_evasion/gandalf` | 0.103 [0.082, 0.131] (62/599) | 0.399 [0.360, 0.439] (239/599) | 0.659 [0.621, 0.696] (395/599) |

Where the gain on the test split came from: LLMail-Inject (0.10 to 0.29 of
attempts, 0.15 to 0.42 of the attacks that reached the tool call), three
AgentDojo templates (0 to 0.93–1.00), and stacked disguises (0.40 to 0.66).
Nothing else moved. Plain requests placed in tool output are still not found
at all: InjecAgent's base setting 0 of 527, AgentDojo's "TODO:" template 0 of
54, BIPIA's plain tasks.

### Harder cases

A payload keeps being found, or not, regardless of the container it is put in
or the document around it. Recall on Gandalf payloads is 0.62 bare, 0.62
embedded in a document, 0.68 in a structured container, 0.68 in a
30,000-character document, 0.68 in a document in another language, and 0.56
when split across two paragraphs. The earlier scanner found 0.16 of the
Gandalf payloads in 30,000-character documents, because it read the first
5,000 characters.

| Container | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.3 |
|---|---|---|---|
| `code_comment` | 0.167 [0.073, 0.336] (5/30) | 0.333 [0.192, 0.512] (10/30) | 0.333 [0.192, 0.512] (10/30) |
| `csv_cell` | 0.033 [0.006, 0.167] (1/30) | 0.300 [0.167, 0.479] (9/30) | 0.300 [0.167, 0.479] (9/30) |
| `email_quote` | 0.100 [0.035, 0.256] (3/30) | 0.200 [0.095, 0.373] (6/30) | 0.200 [0.095, 0.373] (6/30) |
| `footnote` | 0.033 [0.006, 0.167] (1/30) | 0.233 [0.118, 0.409] (7/30) | 0.233 [0.118, 0.409] (7/30) |
| `html_alt` | 0.033 [0.006, 0.167] (1/30) | 0.200 [0.095, 0.373] (6/30) | 0.200 [0.095, 0.373] (6/30) |
| `json_field` | 0.200 [0.095, 0.373] (6/30) | 0.367 [0.219, 0.545] (11/30) | 0.367 [0.219, 0.545] (11/30) |
| `markdown_table` | 0.167 [0.073, 0.336] (5/30) | 0.300 [0.167, 0.479] (9/30) | 0.300 [0.167, 0.479] (9/30) |
| `yaml_front_matter` | 0.067 [0.018, 0.213] (2/30) | 0.167 [0.073, 0.336] (5/30) | 0.167 [0.073, 0.336] (5/30) |

Of the payloads each pack finds in plain form, the share it still finds under
each disguise, including the ten stacked pairs:

| Obfuscation | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.3 |
|---|---|---|---|
| `base64` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `base64+css_hidden` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `base64+url_query` | 0.000 [0.000, 0.110] (0/31) | 0.000 [0.000, 0.084] (0/42) | 1.000 [0.916, 1.000] (42/42) |
| `base64_twice` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `css_hidden` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `fullwidth` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `fullwidth+one_char_per_line` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `hex` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `homoglyph_cyrillic` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.914, 1.000] (41/41) | 1.000 [0.914, 1.000] (41/41) |
| `homoglyph_cyrillic+zero_width_split` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `html_comment` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `html_entities` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `leetspeak` | 0.000 [0.000, 0.110] (0/31) | 0.829 [0.687, 0.915] (34/41) | 0.829 [0.687, 0.915] (34/41) |
| `leetspeak+base64` | 0.000 [0.000, 0.110] (0/31) | 0.000 [0.000, 0.086] (0/41) | 0.829 [0.687, 0.915] (34/41) |
| `leetspeak+html_comment` | 0.000 [0.000, 0.110] (0/31) | 0.833 [0.694, 0.917] (35/42) | 0.833 [0.694, 0.917] (35/42) |
| `letter_spaced` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `one_char_per_line` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `quoted_printable` | 0.000 [0.000, 0.110] (0/31) | 0.976 [0.877, 0.996] (41/42) | 0.976 [0.877, 0.996] (41/42) |
| `reversed` | 0.000 [0.000, 0.110] (0/31) | 0.952 [0.842, 0.987] (40/42) | 0.952 [0.842, 0.987] (40/42) |
| `reversed+base64` | 0.000 [0.000, 0.110] (0/31) | 0.000 [0.000, 0.084] (0/42) | 0.952 [0.842, 0.987] (40/42) |
| `rot13` | 0.000 [0.000, 0.110] (0/31) | 0.976 [0.874, 0.996] (40/41) | 0.976 [0.874, 0.996] (40/41) |
| `rot13+base64` | 0.000 [0.000, 0.110] (0/31) | 0.024 [0.004, 0.123] (1/42) | 0.976 [0.877, 0.996] (41/42) |
| `soft_hyphen_split` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `tag_smuggled` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `typos` | 0.065 [0.018, 0.207] (2/31) | 0.857 [0.722, 0.933] (36/42) | 0.857 [0.722, 0.933] (36/42) |
| `typos+letter_spaced` | 0.000 [0.000, 0.110] (0/31) | 0.833 [0.694, 0.917] (35/42) | 0.833 [0.694, 0.917] (35/42) |
| `unicode_escapes` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `unicode_escapes+html_comment` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `url_encoded` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `url_query` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `variation_selector_smuggled` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |
| `zero_width_split` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.916, 1.000] (42/42) |

Pack 2026.11.1 lost all, or all but one, of the payloads under four of the
stacked pairs (anything inside base64 that needed a second step, and base64
inside a URL-encoded query). Decoded payloads are now given every reading the text itself gets.

### Held-out sources

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Scanner before this work | 0.202 | 0.820 | 0.115 [0.107, 0.123] (732/6362) | 0.019 [0.016, 0.022] (161/8560) | 0.553 [0.548, 0.558] | 0.495 [0.490, 0.499] |
| Rule pack 2026.11.1 | 0.286 | 0.869 | 0.172 [0.162, 0.181] (1091/6362) | 0.019 [0.017, 0.022] (165/8560) | 0.583 [0.578, 0.589] | 0.528 [0.522, 0.533] |
| Rule pack 2026.11.2 (frozen) | 0.286 | 0.873 | 0.171 [0.162, 0.180] (1086/6362) | 0.018 [0.016, 0.021] (158/8560) | 0.584 [0.579, 0.590] | 0.530 [0.524, 0.535] |
| Rule pack 2026.11.3 | 0.278 | 0.990 | 0.161 [0.153, 0.171] (1027/6362) | 0.001 [0.001, 0.002] (10/8560) | 0.585 [0.579, 0.590] | 0.534 [0.529, 0.540] |

| Family / source | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.2 (frozen) | Rule pack 2026.11.3 |
|---|---|---|---|---|
| `labelled_prompt/slabs` | 0.061 [0.051, 0.073] (120/1964) | 0.119 [0.106, 0.134] (234/1964) | 0.117 [0.104, 0.132] (230/1964) | 0.115 [0.101, 0.129] (225/1964) |
| `labelled_prompt/spml` | 0.026 [0.020, 0.035] (53/2000) | 0.039 [0.031, 0.048] (78/2000) | 0.035 [0.028, 0.044] (71/2000) | 0.017 [0.012, 0.023] (33/2000) |
| `labelled_prompt/turkish` | 0.000 [0.000, 0.015] (0/258) | 0.000 [0.000, 0.015] (0/258) | 0.000 [0.000, 0.015] (0/258) | 0.000 [0.000, 0.015] (0/258) |
| `labelled_prompt/wambosec` | 0.280 [0.260, 0.300] (559/2000) | 0.387 [0.366, 0.408] (774/2000) | 0.390 [0.369, 0.412] (780/2000) | 0.382 [0.361, 0.404] (764/2000) |
| `summarization_injection/gandalf_summarization` | 0.000 [0.000, 0.027] (0/140) | 0.036 [0.015, 0.081] (5/140) | 0.036 [0.015, 0.081] (5/140) | 0.036 [0.015, 0.081] (5/140) |

| Source | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.2 (frozen) | Rule pack 2026.11.3 |
|---|---|---|---|---|
| `cursor_rules` | 0.002 [0.000, 0.009] (1/592) | 0.002 [0.000, 0.009] (1/592) | 0.003 [0.001, 0.012] (2/592) | 0.003 [0.001, 0.012] (2/592) |
| `jailbreak` | 0.110 [0.095, 0.128] (146/1323) | 0.110 [0.095, 0.128] (146/1323) | 0.110 [0.095, 0.128] (146/1323) | 0.001 [0.000, 0.004] (1/1323) |
| `notinject` | 0.032 [0.018, 0.057] (11/339) | 0.032 [0.018, 0.057] (11/339) | 0.009 [0.003, 0.026] (3/339) | 0.006 [0.002, 0.021] (2/339) |
| `slabs` | 0.002 [0.001, 0.004] (3/1993) | 0.004 [0.002, 0.007] (7/1993) | 0.004 [0.002, 0.007] (7/1993) | 0.003 [0.001, 0.006] (5/1993) |
| `spml` | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) |
| `turkish` | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) |
| `wambosec` | 0.000 [0.000, 0.002] (0/2000) | 0.000 [0.000, 0.002] (0/2000) | 0.000 [0.000, 0.002] (0/2000) | 0.000 [0.000, 0.002] (0/2000) |

- The rules find 38% of wambosec's attacks, 12% of S-Labs', 4% of the
  Gandalf summarisation texts, 2% to 4% of SPML's, and none of the Turkish
  ones. There are no Turkish rules.
- In the frozen pack, 146 of 1,323 benign prompts in the jailbreak set were
  flagged, 145 of them by `role.pretend`: people asking a chatbot to play a
  character. After the change, 1 is.
- The rule files written for AI coding assistants, which are instructions
  addressed to a model from first line to last, produce 2 flags in 592 chunks.
- NotInject: 2 of 339 (it was 11 with the earlier scanner and with pack
  2026.11.1).

| Family / source | Scanner before this work | Rule pack 2026.11.1 | Rule pack 2026.11.2 (frozen) | Rule pack 2026.11.3 |
|---|---|---|---|---|
| `jailbreak_prompt/jailbreak` | 0.473 [0.435, 0.511] (309/653) | 0.498 [0.460, 0.536] (325/653) | 0.436 [0.399, 0.475] (285/653) | 0.404 [0.367, 0.442] (264/653) |

The scanner flags about four in ten of the jailbreak prompts, by its role and
policy-bypass rules. That figure barely moved with the `role.pretend` change
(0.44 to 0.40): the rule had mostly been firing on benign role-play, not on
jailbreaks.

## Rules with a pre-trained classifier

Two models were scored, both Apache-2.0, not gated, loaded as one ONNX file and
one tokenizer file with no repository code: Horizon Labs'
`prompt-injection-guard-small` and Patronus' `wolf-defender-prompt-injection-small`,
both fine-tuned from mmBERT-small and both released in November 2026. How they
are loaded and what their opinion is allowed to change is in
[the optional injection classifier](../injection_classifier.md). In short: the
fused score is the higher of the rules' score and the classifier's probability
mapped so that its threshold lands on the flagging threshold; a flag that rests
on the classifier alone is never high confidence and never blocks.

Each model was given the scanner's canonical reading of the text, in windows of
2,046 tokens with a 64-token overlap, at most eight windows, the maximum taken.
(Horizon's card uses a smaller step between windows and Wolf's a smooth
maximum; both were simplified to this.) Scored on every benign row of the test
and held-out splits and up to 150 attack rows per family and source: 20,508
rows.

### What each model had already seen

From the model cards. "Not stated" means the card does not mention the source;
it does not mean the model has not seen it.

| Benchmark source | Split here | Horizon | Wolf |
|---|---|---|---|
| Gandalf, yanismiraoui | dev, test | training data | not stated |
| deepset | dev, test | training data (train half) | training data |
| LLMail-Inject phase 2 | dev, test | excluded from training (phase 1 was used) | training data (phase not stated) |
| BIPIA | dev, test | excluded from training | not stated |
| InjecAgent, AgentDojo | dev, test | not stated | not stated |
| S-Labs, wambosec | held-out | **training data** | not stated |
| jailbreak set (jackhhao) | held-out | training data (train half) | not stated |
| SPML, Turkish prompts, Gandalf summarisation | held-out | not stated | not stated |
| NotInject | held-out | excluded from training | not stated |
| AI-assistant rule files | held-out | not stated | not stated |

Wolf's card names three datasets and "a curated multilingual corpus of
public-source and internally developed examples", so no public source can be
called unseen for it.

### Test split

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Rules alone | 0.551 | 0.983 | 0.383 [0.366, 0.401] (1132/2953) | 0.003 [0.002, 0.004] (20/8105) | 0.737 [0.727, 0.746] | 0.612 [0.597, 0.626] |
| Horizon alone | 0.810 | 0.998 | 0.681 [0.664, 0.698] (2012/2953) | 0.001 [0.000, 0.001] (5/8105) | 0.982 [0.979, 0.984] | 0.968 [0.965, 0.972] |
| Rules + Horizon | 0.839 | 0.989 | 0.728 [0.712, 0.744] (2150/2953) | 0.003 [0.002, 0.004] (23/8105) | 0.977 [0.975, 0.980] | 0.950 [0.944, 0.957] |
| Wolf alone | 0.894 | 0.998 | 0.810 [0.796, 0.824] (2393/2953) | 0.001 [0.000, 0.001] (5/8105) | 0.971 [0.966, 0.975] | 0.963 [0.959, 0.968] |
| Rules + Wolf | 0.913 | 0.990 | 0.847 [0.833, 0.859] (2500/2953) | 0.003 [0.002, 0.004] (25/8105) | 0.973 [0.969, 0.977] | 0.954 [0.948, 0.961] |

| Family / source | Rules alone | Horizon alone | Rules + Horizon | Wolf alone | Rules + Wolf |
|---|---|---|---|---|---|
| `agentdojo_direct/agentdojo` | 0.000 [0.000, 0.066] (0/54) | 0.574 [0.442, 0.697] (31/54) | 0.574 [0.442, 0.697] (31/54) | 0.778 [0.651, 0.868] (42/54) | 0.778 [0.651, 0.868] (42/54) |
| `agentdojo_ignore_previous/agentdojo` | 0.926 [0.825, 0.971] (50/54) | 0.926 [0.825, 0.971] (50/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) |
| `agentdojo_important_instructions/agentdojo` | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 0.704 [0.572, 0.809] (38/54) | 1.000 [0.934, 1.000] (54/54) |
| `agentdojo_injecagent/agentdojo` | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) |
| `agentdojo_system_message/agentdojo` | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 1.000 [0.934, 1.000] (54/54) | 0.722 [0.591, 0.824] (39/54) | 1.000 [0.934, 1.000] (54/54) |
| `bipia_code/bipia` | 0.060 [0.032, 0.110] (9/150) | 0.140 [0.093, 0.205] (21/150) | 0.200 [0.144, 0.271] (30/150) | 0.933 [0.882, 0.963] (140/150) | 0.940 [0.890, 0.968] (141/150) |
| `bipia_text/bipia` | 0.147 [0.099, 0.212] (22/150) | 0.267 [0.202, 0.343] (40/150) | 0.347 [0.275, 0.426] (52/150) | 0.753 [0.679, 0.815] (113/150) | 0.753 [0.679, 0.815] (113/150) |
| `container_payload/deepset` | 0.125 [0.043, 0.310] (3/24) | 0.500 [0.314, 0.686] (12/24) | 0.500 [0.314, 0.686] (12/24) | 0.333 [0.180, 0.533] (8/24) | 0.333 [0.180, 0.533] (8/24) |
| `container_payload/gandalf` | 0.676 [0.515, 0.804] (25/37) | 0.757 [0.599, 0.866] (28/37) | 0.919 [0.787, 0.972] (34/37) | 0.622 [0.461, 0.759] (23/37) | 0.865 [0.720, 0.941] (32/37) |
| `container_payload/yanismiraoui` | 0.193 [0.138, 0.264] (29/150) | 0.613 [0.533, 0.688] (92/150) | 0.673 [0.595, 0.743] (101/150) | 0.527 [0.447, 0.605] (79/150) | 0.600 [0.520, 0.675] (90/150) |
| `diluted_payload/deepset` | 0.125 [0.043, 0.310] (3/24) | 0.292 [0.149, 0.492] (7/24) | 0.333 [0.180, 0.533] (8/24) | 0.375 [0.212, 0.573] (9/24) | 0.375 [0.212, 0.573] (9/24) |
| `diluted_payload/gandalf` | 0.676 [0.515, 0.804] (25/37) | 0.595 [0.435, 0.737] (22/37) | 0.757 [0.599, 0.866] (28/37) | 0.892 [0.753, 0.957] (33/37) | 0.919 [0.787, 0.972] (34/37) |
| `diluted_payload/yanismiraoui` | 0.193 [0.138, 0.264] (29/150) | 0.420 [0.344, 0.500] (63/150) | 0.487 [0.408, 0.566] (73/150) | 0.820 [0.751, 0.873] (123/150) | 0.833 [0.765, 0.884] (125/150) |
| `direct_prompt/deepset` | 0.167 [0.093, 0.280] (10/60) | 0.317 [0.213, 0.442] (19/60) | 0.350 [0.242, 0.476] (21/60) | 0.417 [0.301, 0.543] (25/60) | 0.467 [0.346, 0.591] (28/60) |
| `direct_prompt/gandalf` | 0.616 [0.524, 0.701] (69/112) | 0.902 [0.833, 0.944] (101/112) | 0.920 [0.854, 0.957] (103/112) | 0.946 [0.888, 0.975] (106/112) | 0.955 [0.900, 0.981] (107/112) |
| `direct_prompt/yanismiraoui` | 0.213 [0.155, 0.286] (32/150) | 0.933 [0.882, 0.963] (140/150) | 0.933 [0.882, 0.963] (140/150) | 0.933 [0.882, 0.963] (140/150) | 0.933 [0.882, 0.963] (140/150) |
| `embedded_payload/deepset` | 0.167 [0.093, 0.280] (10/60) | 0.467 [0.346, 0.591] (28/60) | 0.483 [0.362, 0.607] (29/60) | 0.567 [0.441, 0.684] (34/60) | 0.567 [0.441, 0.684] (34/60) |
| `embedded_payload/gandalf` | 0.616 [0.524, 0.701] (69/112) | 0.741 [0.653, 0.813] (83/112) | 0.812 [0.730, 0.874] (91/112) | 0.920 [0.854, 0.957] (103/112) | 0.938 [0.877, 0.969] (105/112) |
| `embedded_payload/yanismiraoui` | 0.220 [0.161, 0.293] (33/150) | 0.573 [0.493, 0.650] (86/150) | 0.607 [0.527, 0.681] (91/150) | 0.880 [0.818, 0.923] (132/150) | 0.887 [0.826, 0.928] (133/150) |
| `evasion/gandalf` | 0.687 [0.609, 0.755] (103/150) | 0.747 [0.671, 0.809] (112/150) | 0.907 [0.849, 0.944] (136/150) | 0.813 [0.743, 0.868] (122/150) | 0.960 [0.915, 0.982] (144/150) |
| `foreign_carrier_payload/deepset` | 0.125 [0.043, 0.310] (3/24) | 0.750 [0.551, 0.880] (18/24) | 0.750 [0.551, 0.880] (18/24) | 0.708 [0.508, 0.851] (17/24) | 0.708 [0.508, 0.851] (17/24) |
| `foreign_carrier_payload/gandalf` | 0.676 [0.515, 0.804] (25/37) | 1.000 [0.906, 1.000] (37/37) | 1.000 [0.906, 1.000] (37/37) | 0.973 [0.862, 0.995] (36/37) | 0.973 [0.862, 0.995] (36/37) |
| `foreign_carrier_payload/yanismiraoui` | 0.207 [0.150, 0.278] (31/150) | 0.927 [0.874, 0.959] (139/150) | 0.927 [0.874, 0.959] (139/150) | 0.927 [0.874, 0.959] (139/150) | 0.927 [0.874, 0.959] (139/150) |
| `injecagent_base/injecagent` | 0.000 [0.000, 0.025] (0/150) | 0.513 [0.434, 0.592] (77/150) | 0.513 [0.434, 0.592] (77/150) | 0.540 [0.460, 0.618] (81/150) | 0.540 [0.460, 0.618] (81/150) |
| `injecagent_enhanced/injecagent` | 1.000 [0.975, 1.000] (150/150) | 1.000 [0.975, 1.000] (150/150) | 1.000 [0.975, 1.000] (150/150) | 1.000 [0.975, 1.000] (150/150) | 1.000 [0.975, 1.000] (150/150) |
| `llmail_attempt/llmail` | 0.253 [0.191, 0.329] (38/150) | 0.960 [0.915, 0.982] (144/150) | 0.960 [0.915, 0.982] (144/150) | 0.947 [0.898, 0.973] (142/150) | 0.947 [0.898, 0.973] (142/150) |
| `llmail_succeeded/llmail` | 0.360 [0.288, 0.439] (54/150) | 0.993 [0.963, 0.999] (149/150) | 0.993 [0.963, 0.999] (149/150) | 0.947 [0.898, 0.973] (142/150) | 0.960 [0.915, 0.982] (144/150) |
| `split_payload/deepset` | 0.125 [0.043, 0.310] (3/24) | 0.375 [0.212, 0.573] (9/24) | 0.458 [0.279, 0.649] (11/24) | 0.500 [0.314, 0.686] (12/24) | 0.500 [0.314, 0.686] (12/24) |
| `split_payload/gandalf` | 0.562 [0.393, 0.718] (18/32) | 0.625 [0.453, 0.771] (20/32) | 0.719 [0.546, 0.844] (23/32) | 0.750 [0.579, 0.868] (24/32) | 0.781 [0.612, 0.890] (25/32) |
| `split_payload/yanismiraoui` | 0.173 [0.121, 0.242] (26/150) | 0.380 [0.306, 0.460] (57/150) | 0.473 [0.395, 0.553] (71/150) | 0.720 [0.643, 0.786] (108/150) | 0.740 [0.664, 0.804] (111/150) |
| `stacked_evasion/gandalf` | 0.673 [0.595, 0.743] (101/150) | 0.767 [0.693, 0.827] (115/150) | 0.900 [0.842, 0.939] (135/150) | 0.833 [0.765, 0.884] (125/150) | 0.947 [0.898, 0.973] (142/150) |

| Source | Rules alone | Horizon alone | Rules + Horizon | Wolf alone | Rules + Wolf |
|---|---|---|---|---|---|
| `agentdojo` | 0.000 [0.000, 0.259] (0/11) | 0.000 [0.000, 0.259] (0/11) | 0.000 [0.000, 0.259] (0/11) | 0.000 [0.000, 0.259] (0/11) | 0.000 [0.000, 0.259] (0/11) |
| `bipia` | 0.000 [0.000, 0.030] (0/125) | 0.008 [0.001, 0.044] (1/125) | 0.008 [0.001, 0.044] (1/125) | 0.000 [0.000, 0.030] (0/125) | 0.000 [0.000, 0.030] (0/125) |
| `deepset` | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) |
| `django_docs` | 0.000 [0.000, 0.003] (0/1207) | 0.000 [0.000, 0.003] (0/1207) | 0.000 [0.000, 0.003] (0/1207) | 0.000 [0.000, 0.003] (0/1207) | 0.000 [0.000, 0.003] (0/1207) |
| `llmail` | 0.000 [0.000, 0.042] (0/88) | 0.000 [0.000, 0.042] (0/88) | 0.000 [0.000, 0.042] (0/88) | 0.000 [0.000, 0.042] (0/88) | 0.000 [0.000, 0.042] (0/88) |
| `owasp_cheatsheets` | 0.017 [0.009, 0.032] (10/576) | 0.000 [0.000, 0.007] (0/576) | 0.017 [0.009, 0.032] (10/576) | 0.007 [0.003, 0.018] (4/576) | 0.024 [0.015, 0.040] (14/576) |
| `prompt_guide` | 0.047 [0.025, 0.087] (9/192) | 0.021 [0.008, 0.052] (4/192) | 0.057 [0.032, 0.100] (11/192) | 0.005 [0.001, 0.029] (1/192) | 0.052 [0.029, 0.093] (10/192) |
| `runbooks_openshift` | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.014] (0/267) |
| `runbooks_prometheus` | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) |
| `tldr_pages` | 0.001 [0.000, 0.004] (1/1500) | 0.000 [0.000, 0.003] (0/1500) | 0.001 [0.000, 0.004] (1/1500) | 0.000 [0.000, 0.003] (0/1500) | 0.001 [0.000, 0.004] (1/1500) |
| `wikipedia_ar` | 0.000 [0.000, 0.012] (0/309) | 0.000 [0.000, 0.012] (0/309) | 0.000 [0.000, 0.012] (0/309) | 0.000 [0.000, 0.012] (0/309) | 0.000 [0.000, 0.012] (0/309) |
| `wikipedia_de` | 0.000 [0.000, 0.011] (0/357) | 0.000 [0.000, 0.011] (0/357) | 0.000 [0.000, 0.011] (0/357) | 0.000 [0.000, 0.011] (0/357) | 0.000 [0.000, 0.011] (0/357) |
| `wikipedia_en` | 0.000 [0.000, 0.003] (0/1159) | 0.000 [0.000, 0.003] (0/1159) | 0.000 [0.000, 0.003] (0/1159) | 0.000 [0.000, 0.003] (0/1159) | 0.000 [0.000, 0.003] (0/1159) |
| `wikipedia_es` | 0.000 [0.000, 0.011] (0/346) | 0.000 [0.000, 0.011] (0/346) | 0.000 [0.000, 0.011] (0/346) | 0.000 [0.000, 0.011] (0/346) | 0.000 [0.000, 0.011] (0/346) |
| `wikipedia_fa` | 0.000 [0.000, 0.014] (0/271) | 0.000 [0.000, 0.014] (0/271) | 0.000 [0.000, 0.014] (0/271) | 0.000 [0.000, 0.014] (0/271) | 0.000 [0.000, 0.014] (0/271) |
| `wikipedia_fr` | 0.000 [0.000, 0.011] (0/337) | 0.000 [0.000, 0.011] (0/337) | 0.000 [0.000, 0.011] (0/337) | 0.000 [0.000, 0.011] (0/337) | 0.000 [0.000, 0.011] (0/337) |
| `wikipedia_he` | 0.000 [0.000, 0.011] (0/359) | 0.000 [0.000, 0.011] (0/359) | 0.000 [0.000, 0.011] (0/359) | 0.000 [0.000, 0.011] (0/359) | 0.000 [0.000, 0.011] (0/359) |
| `wikipedia_ja` | 0.000 [0.000, 0.011] (0/329) | 0.000 [0.000, 0.011] (0/329) | 0.000 [0.000, 0.011] (0/329) | 0.000 [0.000, 0.011] (0/329) | 0.000 [0.000, 0.011] (0/329) |
| `wikipedia_ru` | 0.000 [0.000, 0.011] (0/339) | 0.000 [0.000, 0.011] (0/339) | 0.000 [0.000, 0.011] (0/339) | 0.000 [0.000, 0.011] (0/339) | 0.000 [0.000, 0.011] (0/339) |
| `wikipedia_zh` | 0.000 [0.000, 0.017] (0/221) | 0.000 [0.000, 0.017] (0/221) | 0.000 [0.000, 0.017] (0/221) | 0.000 [0.000, 0.017] (0/221) | 0.000 [0.000, 0.017] (0/221) |

### Held-out sources

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Rules alone | 0.208 | 0.897 | 0.118 [0.096, 0.143] (87/740) | 0.001 [0.001, 0.002] (10/8560) | 0.557 [0.545, 0.570] | 0.188 [0.169, 0.209] |
| Horizon alone | 0.656 | 0.981 | 0.493 [0.457, 0.529] (365/740) | 0.001 [0.000, 0.002] (7/8560) | 0.958 [0.950, 0.966] | 0.828 [0.810, 0.851] |
| Rules + Horizon | 0.656 | 0.958 | 0.499 [0.463, 0.535] (369/740) | 0.002 [0.001, 0.003] (16/8560) | 0.946 [0.938, 0.955] | 0.768 [0.749, 0.795] |
| Wolf alone | 0.732 | 0.911 | 0.612 [0.577, 0.647] (453/740) | 0.005 [0.004, 0.007] (44/8560) | 0.964 [0.956, 0.972] | 0.848 [0.829, 0.867] |
| Rules + Wolf | 0.734 | 0.898 | 0.620 [0.585, 0.654] (459/740) | 0.006 [0.005, 0.008] (52/8560) | 0.953 [0.944, 0.962] | 0.783 [0.762, 0.805] |

| Family / source | Rules alone | Horizon alone | Rules + Horizon | Wolf alone | Rules + Wolf |
|---|---|---|---|---|---|
| `labelled_prompt/slabs` | 0.120 [0.077, 0.182] (18/150) | 0.827 [0.758, 0.879] (124/150) | 0.827 [0.758, 0.879] (124/150) | 0.813 [0.743, 0.868] (122/150) | 0.813 [0.743, 0.868] (122/150) |
| `labelled_prompt/spml` | 0.033 [0.014, 0.076] (5/150) | 0.067 [0.037, 0.118] (10/150) | 0.073 [0.041, 0.127] (11/150) | 0.107 [0.067, 0.166] (16/150) | 0.113 [0.072, 0.174] (17/150) |
| `labelled_prompt/turkish` | 0.000 [0.000, 0.025] (0/150) | 0.200 [0.144, 0.271] (30/150) | 0.200 [0.144, 0.271] (30/150) | 0.440 [0.363, 0.520] (66/150) | 0.440 [0.363, 0.520] (66/150) |
| `labelled_prompt/wambosec` | 0.393 [0.319, 0.473] (59/150) | 0.907 [0.849, 0.944] (136/150) | 0.927 [0.874, 0.959] (139/150) | 0.800 [0.729, 0.856] (120/150) | 0.833 [0.765, 0.884] (125/150) |
| `summarization_injection/gandalf_summarization` | 0.036 [0.015, 0.081] (5/140) | 0.464 [0.384, 0.547] (65/140) | 0.464 [0.384, 0.547] (65/140) | 0.921 [0.865, 0.956] (129/140) | 0.921 [0.865, 0.956] (129/140) |

| Source | Rules alone | Horizon alone | Rules + Horizon | Wolf alone | Rules + Wolf |
|---|---|---|---|---|---|
| `cursor_rules` | 0.003 [0.001, 0.012] (2/592) | 0.000 [0.000, 0.006] (0/592) | 0.003 [0.001, 0.012] (2/592) | 0.007 [0.003, 0.017] (4/592) | 0.010 [0.005, 0.022] (6/592) |
| `jailbreak` | 0.001 [0.000, 0.004] (1/1323) | 0.001 [0.000, 0.004] (1/1323) | 0.002 [0.000, 0.005] (2/1323) | 0.002 [0.001, 0.007] (3/1323) | 0.003 [0.001, 0.008] (4/1323) |
| `notinject` | 0.006 [0.002, 0.021] (2/339) | 0.000 [0.000, 0.011] (0/339) | 0.006 [0.002, 0.021] (2/339) | 0.024 [0.012, 0.046] (8/339) | 0.024 [0.012, 0.046] (8/339) |
| `slabs` | 0.003 [0.001, 0.006] (5/1993) | 0.003 [0.001, 0.007] (6/1993) | 0.005 [0.003, 0.009] (10/1993) | 0.001 [0.000, 0.003] (1/1993) | 0.003 [0.001, 0.007] (6/1993) |
| `spml` | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) | 0.000 [0.000, 0.002] (0/1955) |
| `turkish` | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) | 0.000 [0.000, 0.011] (0/358) |
| `wambosec` | 0.000 [0.000, 0.002] (0/2000) | 0.000 [0.000, 0.002] (0/2000) | 0.000 [0.000, 0.002] (0/2000) | 0.014 [0.010, 0.020] (28/2000) | 0.014 [0.010, 0.020] (28/2000) |

Reading these:

- **The classifiers do most of the finding; the rules add a little recall and
  most of the explanation.** On the test split the rules add 3 to 5 points of
  recall to either model. On held-out data they add under one.
- **Fusing costs false positives, and a little ranking.** A fused flag is a
  flag from either layer, so the fused false-positive rate is about the sum of
  the two: on held-out data Horizon alone is at 0.08% and fused at 0.19%. And
  the fused ROC-AUC is slightly below the model's own on held-out data (0.946
  against 0.958 for Horizon, 0.953 against 0.964 for Wolf), because a rule's
  supporting signal on a benign text outranks a low model probability on an
  attack. If the only goal were these two numbers, the model alone would win
  on held-out data. The rules are kept beside it for what they do that a model
  does not: they read disguised text, they point at a span and a rule a
  reviewer can check, and they are the only layer allowed to block.
- **Horizon is the more conservative of the two, Wolf finds more.** On
  held-out data Wolf's recall is 0.61 against Horizon's 0.49, and its
  false-positive rate 0.51% against 0.08%: Wolf flags 28 of 2,000 benign
  wambosec prompts and 8 of 339 NotInject sentences where Horizon flags none.
- **SPML defeats everything**: 4% to 12%. Its attacks are user prompts that
  contradict a chatbot's system prompt, and are attacks only in the light of
  that system prompt, which no detector here is shown.

### Held-out sources outside Horizon's listed training data

Attacks from SPML, the Turkish set and Gandalf summarisation (440 sampled
rows); benign rows from SPML, the Turkish set, the AI-assistant rule files and
NotInject (3,244 rows).

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC |
|---|---|---|---|---|---|
| Rules alone | 0.044 | 0.714 | 0.023 [0.012, 0.041] (10/440) | 0.001 [0.001, 0.003] (4/3244) | 0.490 [0.480, 0.500] |
| Horizon alone | 0.385 | 1.000 | 0.239 [0.201, 0.281] (105/440) | 0.000 [0.000, 0.001] (0/3244) | 0.938 [0.924, 0.947] |
| Rules + Horizon | 0.386 | 0.964 | 0.241 [0.203, 0.283] (106/440) | 0.001 [0.001, 0.003] (4/3244) | 0.916 [0.901, 0.926] |
| Wolf alone | 0.636 | 0.946 | 0.479 [0.433, 0.526] (211/440) | 0.004 [0.002, 0.006] (12/3244) | 0.956 [0.943, 0.967] |
| Rules + Wolf | 0.637 | 0.938 | 0.482 [0.435, 0.528] (212/440) | 0.004 [0.003, 0.007] (14/3244) | 0.934 [0.921, 0.946] |

This is the closest thing on this page to an out-of-sample figure for a
classifier, and it is for Horizon only; nothing is known to be out of sample
for Wolf. Recall here is a quarter for Horizon and a half for Wolf, with the
rules contributing one attack. ROC-AUC stays above 0.93 for both models, so
their ranking carries over better than their recall at a fixed threshold.

### Frozen and adjusted, side by side

The fused figures above use rule pack 2026.11.3. With the pack as frozen:

| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|
| Rules 2026.11.2 + Horizon (frozen) | 0.581 | 0.693 | 0.500 [0.464, 0.536] (370/740) | 0.019 [0.017, 0.022] (164/8560) | 0.944 [0.936, 0.953] | 0.739 [0.719, 0.767] |
| Rules 2026.11.3 + Horizon | 0.656 | 0.958 | 0.499 [0.463, 0.535] (369/740) | 0.002 [0.001, 0.003] (16/8560) | 0.946 [0.938, 0.955] | 0.768 [0.749, 0.795] |
| Rules 2026.11.2 + Wolf (frozen) | 0.657 | 0.697 | 0.622 [0.586, 0.656] (460/740) | 0.023 [0.020, 0.027] (200/8560) | 0.952 [0.944, 0.961] | 0.779 [0.757, 0.802] |
| Rules 2026.11.3 + Wolf | 0.734 | 0.898 | 0.620 [0.585, 0.654] (459/740) | 0.006 [0.005, 0.008] (52/8560) | 0.953 [0.944, 0.962] | 0.783 [0.762, 0.805] |

The difference is the 146 role-play prompts. Test-split figures are the same
for both packs.

## Which rules did the work

Rule pack 2026.11.3 on the test and held-out rows together, the 28 rules that
fired most on attacks:

| Rule | Fired on attacks | Fired on benign | Precision on this mix | Benign fire rate |
|---|---|---|---|---|
| `override.previous_instructions` | 4482 | 11 | 0.998 [0.996, 0.999] (4482/4493) | 0.000 [0.000, 0.001] (11/24848) |
| `override.all_instructions` | 3243 | 5 | 0.999 [0.996, 0.999] (3243/3248) | 0.000 [0.000, 0.001] (5/24848) |
| `delimiter.turn_tags` | 2203 | 13 | 0.994 [0.990, 0.997] (2203/2216) | 0.001 [0.000, 0.001] (13/24848) |
| `hijack.after_task_then_act` | 1711 | 0 | 1.000 [0.998, 1.000] (1711/1711) | 0.000 [0.000, 0.000] (0/24848) |
| `override.abandon_your_rules` | 844 | 2 | 0.998 [0.991, 0.999] (844/846) | 0.000 [0.000, 0.000] (2/24848) |
| `override.your_instructions` | 792 | 2 | 0.998 [0.991, 0.999] (792/794) | 0.000 [0.000, 0.000] (2/24848) |
| `exfil.repeat_instructions` | 629 | 7 | 0.989 [0.978, 0.995] (629/636) | 0.000 [0.000, 0.001] (7/24848) |
| `impersonation.tagged_turn` | 517 | 1 | 0.998 [0.989, 1.000] (517/518) | 0.000 [0.000, 0.000] (1/24848) |
| `override.previous_directions` | 507 | 11 | 0.979 [0.962, 0.988] (507/518) | 0.000 [0.000, 0.001] (11/24848) |
| `delimiter.chat_tokens` | 505 | 32 | 0.940 [0.917, 0.958] (505/537) | 0.001 [0.001, 0.002] (32/24848) |
| `hidden.markup` | 395 | 2 | 0.995 [0.982, 0.999] (395/397) | 0.000 [0.000, 0.000] (2/24848) |
| `exfil.reveal_prompt` | 388 | 4 | 0.990 [0.974, 0.996] (388/392) | 0.000 [0.000, 0.000] (4/24848) |
| `override.new_instructions` | 232 | 0 | 1.000 [0.984, 1.000] (232/232) | 0.000 [0.000, 0.000] (0/24848) |
| `response.in_your_answer` | 210 | 1 | 0.995 [0.974, 0.999] (210/211) | 0.000 [0.000, 0.000] (1/24848) |
| `tool.call_json` | 196 | 1 | 0.995 [0.972, 0.999] (196/197) | 0.000 [0.000, 0.000] (1/24848) |
| `override.what_you_were_told` | 187 | 0 | 1.000 [0.980, 1.000] (187/187) | 0.000 [0.000, 0.000] (0/24848) |
| `role.named_mode` | 154 | 3 | 0.981 [0.945, 0.994] (154/157) | 0.000 [0.000, 0.000] (3/24848) |
| `override.your_new_task` | 148 | 0 | 1.000 [0.975, 1.000] (148/148) | 0.000 [0.000, 0.000] (0/24848) |
| `authority.message_from_me_to_you` | 133 | 0 | 1.000 [0.972, 1.000] (133/133) | 0.000 [0.000, 0.000] (0/24848) |
| `impersonation.system_message_marker` | 133 | 0 | 1.000 [0.972, 1.000] (133/133) | 0.000 [0.000, 0.000] (0/24848) |
| `bypass.safety` | 132 | 5 | 0.964 [0.917, 0.984] (132/137) | 0.000 [0.000, 0.001] (5/24848) |
| `override.original_instructions` | 116 | 3 | 0.975 [0.928, 0.991] (116/119) | 0.000 [0.000, 0.000] (3/24848) |
| `role.you_are_now` | 105 | 3 | 0.972 [0.921, 0.991] (105/108) | 0.000 [0.000, 0.000] (3/24848) |
| `de.override` | 95 | 0 | 1.000 [0.961, 1.000] (95/95) | 0.000 [0.000, 0.000] (0/24848) |
| `override.forget_everything` | 90 | 0 | 1.000 [0.959, 1.000] (90/90) | 0.000 [0.000, 0.000] (0/24848) |
| `hijack.before_you_continue` | 72 | 0 | 1.000 [0.949, 1.000] (72/72) | 0.000 [0.000, 0.000] (0/24848) |
| `fr.override` | 67 | 2 | 0.971 [0.900, 0.992] (67/69) | 0.000 [0.000, 0.000] (2/24848) |
| `role.pretend_unrestricted` | 59 | 1 | 0.983 [0.911, 0.997] (59/60) | 0.000 [0.000, 0.000] (1/24848) |

The full table is in `recorded/2026-11-18-round2-per-rule.json`.

## Speed

One process, Apple M4 Pro, Python 3.12.13:

| Detector | Characters scored | ms per 1,000 characters | Slowest row |
|---|---|---|---|
| Rule pack 2026.11.3, whole text | 68,808,360 | 1.59 | 195 ms |
| Horizon small (quantised ONNX, CPU) | 24,936,170 | 54.3 | 3533 ms |
| Wolf small (quantised ONNX, CPU) | 24,936,170 | 55.2 | 3821 ms |

The rules cost about half as much again as pack 2026.11.1 did (1.08 ms per
1,000 characters on the first round's data), the price of reading every
decoded payload in full. The two model runs shared the machine with each
other, so their figures are an upper bound; either is roughly 35 times the
rules.

## What this benchmark does not show

- **Recall against an attacker who is trying.** Apart from LLMail-Inject, the
  attacks are static. Published adaptive attacks defeat every detector tested
  against them ([Nasr et al. 2025](https://arxiv.org/abs/2510.09023)),
  classifiers included.
- **An out-of-sample figure for the classifiers.** See the table of what each
  had seen. The models were also chosen and their thresholds set on a dev
  split made largely of their own training sources.
- **Precision in a real store.** See "How to read the numbers".
- **Knowledge poisoning.** A false statement with no instruction in it is not
  in the dataset and is not what any layer here looks for.
- **Languages beyond these.** Attack data here is English, six other European
  languages, and Turkish. The rules for Russian, Chinese, Japanese and Arabic
  are covered only by their own examples.
- **The classifiers on every row.** They were scored on 20,508 of 34,290 test
  and held-out rows: all benign rows, a sample of attacks.
- **The x86 build of Wolf**, which is a different file.
- **Span accuracy**, and **label quality**: deepset's and SPML's labels are
  used as published.
- **A committed revision.** The code was an uncommitted working tree on top of
  `0041576` when these runs were made.

## Reproduce

```bash
pip install -e . -r benchmarks/injection/requirements.txt
python benchmarks/injection/fetch.py
python benchmarks/injection/build.py          # prints the dataset sha256
python benchmarks/injection/run.py --detectors legacy vecshield --tag final
python benchmarks/injection/report.py --detectors "Before=legacy.final" "Now=vecshield.final"
```

With a classifier (place the model files as described in
[the classifier page](../injection_classifier.md)):

```bash
pip install onnxruntime tokenizers
python benchmarks/injection/run.py --detectors horizon_small --model-dir /path/to/model \
    --sample 200 --all-negatives --splits dev --tag dev --canonical-input
python benchmarks/injection/run.py --detectors horizon_small --model-dir /path/to/model \
    --sample 150 --all-negatives --splits test heldout --tag final --canonical-input
python benchmarks/injection/fuse.py --classifier horizon_small --scanner-tag final \
    --classifier-tag final --threshold-tag dev --out-tag fused
```

`fetch.py` fails if any downloaded file differs from `sources.lock.json`. This
benchmark is not a CI gate: it was run by hand, and the figures above are the
recorded output of those runs.
