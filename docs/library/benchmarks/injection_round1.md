# Prompt-injection detection on public data: first round

> This is the record of the first benchmark round (dataset `78ed55b9`, rule
> pack `2026.11.1`), kept as it was written. The current figures, on twice the
> data and with F1 and AUC, are in [injection.md](injection.md). The sources
> this page calls "held out" (InjecAgent, LLMail-Inject) were split into dev
> and test in the second round, after this page's figures were recorded.

Measured 2026-11-18. Harness: [`benchmarks/injection/`](../../../benchmarks/injection/).
Recorded summaries: the `2026-11-18-*` files without `round2` in [`benchmarks/injection/recorded/`](../../../benchmarks/injection/recorded/).

This page reports how the injection scanner (`vecshield.injection`, rule pack
`2026.11.1`) performs on public attack data and on ordinary documents, how that
compares with the scanner it replaces, and how a widely used pre-trained
classifier does on the same rows. It also says what was not measured.

## Summary

| | Scanner before | Scanner now | ProtectAI DeBERTa v2 (sampled) |
|---|---|---|---|
| Recall, test split | 0.160 | **0.437** | 0.641 |
| False-positive rate, test split | 0.0023 | 0.0030 | 0.123 |
| Recall, held-out sources | 0.246 | **0.264** | 0.645 |
| False-positive rate, held-out sources | 0.022 | 0.022 | 0.291 |
| Recall at a false-positive rate of 1% or less, test split | 0.172 | 0.443 | 0.471 |
| Recall at a false-positive rate of 1% or less, held-out | 0.244 | 0.259 | 0.009 |
| Milliseconds per 1,000 characters, one CPU core | 0.76 ¹ | 1.08 | 55.2 |

¹ The earlier scanner read only the first 5,000 characters of each text; the
figure divides its time by all the characters in the dataset, so it flatters it.

Four things to take from this:

1. **On data like the data it was developed against, recall rose from 16% to
   44%, at about the same false-positive rate.** The test split is the unseen
   half of sources whose other half was used to write rules.
2. **On sources it was not developed against, recall barely moved: 25% to
   26%.** This is the number to expect in the field. The scanner finds roughly
   a quarter of planted instructions in document-shaped text from elsewhere,
   and seven in ten of the ones it finds there come from one benchmark setting
   that prefixes every attack with "Ignore all previous instructions". The gain
   on the test split did not transfer.
3. **Every false positive on the test split is in a document that discusses
   or quotes injection attacks.** On the other 5,868 benign test rows the
   scanner flagged none (95% upper bound 0.0007). On held-out benign text it
   flagged 11 of 339 sentences built to contain trigger words, and none of 160
   benign emails.
4. **The pre-trained classifier finds far more and cannot be used as it
   stands.** At its default threshold it flagged 15% of ordinary documents,
   93% of Hebrew and 57% of Arabic Wikipedia chunks, and 43% of the
   trigger-word sentences. At a false-positive rate held to 1% it finds about
   what the scanner finds on the test split and almost nothing on held-out
   data. That shapes the next phase; see "What this means for a classifier
   layer".

## How to read the numbers

- **Recall** is the share of attack rows flagged. **False-positive rate** is
  the share of benign rows flagged. Each is given as `value [95% Wilson
  interval] (count/total)`, at the detector's own default threshold.
- **Recall at a false-positive rate** picks the score threshold that keeps the
  false-positive rate at or under the target, on the same rows it is then
  scored on. It is the detector's best case at that rate, not a setting anyone
  chose in advance. With 499 held-out benign rows, a 0.1% target allows no
  false positive at all.
- A rate over fewer than five rows is not reported.
- The mix of attack and benign rows is the benchmark's, not a store's. Real
  stores hold far fewer attacks, so precision in the field will be lower than
  any ratio computed here. That is why false-positive rate, which does not
  depend on the mix, is reported instead of precision.

## What was measured

Dataset SHA-256 `78ed55b936587ccf3d190a4fd5423f974d02ce12bb925febb66b0d1973e96df0`,
26,840 rows, built deterministically from pinned sources
([list and licences](../../../benchmarks/injection/README.md#sources-and-licences)).

| Split | Attack rows | Benign rows | What it is |
|---|---|---|---|
| dev | 4,206 | 6,745 | Half of each developed-against source. Rules were written against it. |
| test | 3,146 | 6,636 | The other half. Not read while writing rules. |
| held-out | 5,608 | 499 | Whole sources never read while writing rules. |

Attack rows:

- **Direct prompts** as published: Gandalf (human-written, English), deepset
  (English and German), yanismiraoui (seven European languages).
- **Embedded payloads**: the same prompts placed as a paragraph inside a
  benign document, at the start, middle or end, in documents of about 500,
  2,000 and 8,000 characters. This is the form a retrieval corpus holds.
- **Evasion**: 60 Gandalf payloads per split, plain and under each of 22
  obfuscations.
- **BIPIA**: its attack strings in its own email, table and code contexts.
- **Held out**: InjecAgent (attacker instructions inside tool output, with and
  without an "ignore previous instructions" prefix) and LLMail-Inject (emails
  written by challenge participants to attack an email assistant that had
  injection defences, 2,000 judged attempts and 1,500 that reached the tool
  call).

Benign rows: chunks of alert runbooks, Django documentation, OWASP cheat
sheets, a prompt-engineering guide, Wikipedia in ten languages, BIPIA's
contexts without an attack, deepset's benign prompts, each carrier document
without its payload, and, held out, NotInject and LLMail-Inject's benign
emails.

Detectors:

- **Scanner before**: `vecshield_platform/integrity/injection.py` at commit
  `0041576`, called as the integrity engine called it (first 5,000 characters).
- **Scanner now**: `vecshield.injection.scan_text`, whole text.
- **ProtectAI DeBERTa v2**: `protectai/deberta-v3-base-prompt-injection-v2`
  (Apache-2.0, revision `90c9989b`, ONNX file SHA-256 `f0ea7f23…47b228c`),
  512-token windows with overlap, the maximum over the first eight windows,
  threshold 0.5. Scored on a fixed sample of at most 1,000 rows per group
  (8,777 rows of the test and held-out splits) because it is about fifty times
  slower.

## How the rules were developed, and what that does to these numbers

The order of work matters to how far the figures can be trusted, so it is
stated in full.

1. The harness and dataset were built first, and the earlier scanner was
   scored on all of it before any rule was changed.
2. Rules were then written and adjusted in two rounds, reading misses and
   false positives **on the dev split only**. While the file formats were
   being learned, before any rule was written, a handful of records outside
   the dev split were printed: one to three from each held-out source, two
   deepset test rows, six BIPIA test attack strings with BIPIA's category
   names, and one BIPIA context of each kind. No other held-out or test row
   was read, and no per-row output of those splits was inspected.
3. The rule pack was frozen, and the test and held-out figures on this page
   come from the run after the freeze. Aggregate figures for those splits were
   visible between the two rounds (the runner prints them), so the test split
   is not blind in the strict sense; the held-out figures did not move between
   rounds and nothing was changed in response to them.
4. Two bugs in how hidden markup is marked were fixed after the freeze, from
   unit tests. The recall and false-positive figures were identical before and
   after.

What follows from that:

- **The test split overstates what to expect elsewhere.** Its rows come from
  the same sources and generators as the rows the rules were written against.
  One of those sources, yanismiraoui, is machine-generated text with a
  recognisable style, and the rules written for it will not generalise as its
  test half suggests.
- **The held-out figure is the honest estimate, and it is low.**
- The public sources are well known. Whoever writes rules for this problem has
  seen examples like them; the held-out split controls for reading these rows,
  not for familiarity with the genre.

## Results on the test split

| Detector | Recall | False-positive rate | Recall at FPR ≤ 0.1% | Recall at FPR ≤ 1% |
|---|---|---|---|---|
| Scanner before this work | 0.160 [0.147, 0.173] (502/3146) | 0.002 [0.001, 0.004] (15/6636) | 0.118 (threshold 0.9, FPR 0.00075) | 0.172 (threshold 0.4, FPR 0.00512) |
| Scanner now | 0.437 [0.420, 0.455] (1375/3146) | 0.003 [0.002, 0.005] (20/6636) | 0.238 (threshold 0.95, FPR 0.0009) | 0.443 (threshold 0.4, FPR 0.00573) |
| ProtectAI DeBERTa v2 | 0.641 [0.623, 0.658] (1774/2769) | 0.123 [0.108, 0.141] (186/1509) | 0.334 (threshold 1.0, FPR 0.00066) | 0.471 (threshold 0.9996, FPR 0.00994) |

### By attack family

| Family / source | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `bipia_code/bipia` | 0.000 [0.000, 0.025] (0/150) | 0.060 [0.032, 0.110] (9/150) | 0.000 [0.000, 0.025] (0/150) |
| `bipia_text/bipia` | 0.000 [0.000, 0.017] (0/224) | 0.147 [0.107, 0.200] (33/224) | 0.348 [0.289, 0.413] (78/224) |
| `direct_prompt/deepset` | 0.067 [0.026, 0.159] (4/60) | 0.167 [0.093, 0.280] (10/60) | 0.367 [0.256, 0.493] (22/60) |
| `direct_prompt/gandalf` | 0.411 [0.324, 0.503] (46/112) | 0.616 [0.524, 0.701] (69/112) | 1.000 [0.967, 1.000] (112/112) |
| `direct_prompt/yanismiraoui` | 0.006 [0.002, 0.017] (3/509) | 0.214 [0.181, 0.252] (109/509) | 0.973 [0.954, 0.984] (495/509) |
| `embedded_payload/deepset` | 0.067 [0.026, 0.159] (4/60) | 0.167 [0.093, 0.280] (10/60) | 0.083 [0.036, 0.181] (5/60) |
| `embedded_payload/gandalf` | 0.339 [0.258, 0.431] (38/112) | 0.616 [0.524, 0.701] (69/112) | 0.500 [0.409, 0.591] (56/112) |
| `embedded_payload/yanismiraoui` | 0.004 [0.001, 0.013] (2/542) | 0.216 [0.183, 0.252] (117/542) | 0.395 [0.355, 0.437] (214/542) |
| `evasion/gandalf` | 0.294 [0.271, 0.319] (405/1377) | 0.689 [0.664, 0.713] (949/1377) | 0.792 [0.766, 0.816] (792/1000) |

Placing a payload inside a document does not change whether the scanner finds
it: Gandalf prompts are found at 0.616 bare and 0.616 embedded. The classifier
loses half of them when they are embedded (1.000 to 0.500), which is the
effect [Liu 2026](https://arxiv.org/abs/2610.03448) reports for detectors
trained on short prompts.

### By position and document length

| Position | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `end` | 0.055 [0.032, 0.092] (13/237) | 0.270 [0.217, 0.330] (64/237) | 0.300 [0.245, 0.361] (71/237) |
| `middle` | 0.089 [0.059, 0.132] (21/237) | 0.300 [0.245, 0.361] (71/237) | 0.338 [0.280, 0.400] (80/237) |
| `start` | 0.042 [0.023, 0.075] (10/240) | 0.254 [0.203, 0.313] (61/240) | 0.517 [0.454, 0.579] (124/240) |

| Length | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `2000` | 0.076 [0.048, 0.116] (18/238) | 0.286 [0.232, 0.346] (68/238) | 0.210 [0.163, 0.266] (50/238) |
| `500` | 0.063 [0.039, 0.101] (15/238) | 0.277 [0.224, 0.337] (66/238) | 0.664 [0.602, 0.721] (158/238) |
| `8000` | 0.046 [0.026, 0.081] (11/238) | 0.261 [0.209, 0.320] (62/238) | 0.281 [0.228, 0.342] (67/238) |

The earlier scanner lost payloads late in long documents to its 5,000-character
cut. The scanner now is flat across position and length. The classifier is
strongest when the payload is at the start of a short document and falls from
0.664 at 500 characters to 0.210 at 2,000.

### Disguised payloads

Of the payloads each detector finds in plain form, the share it still finds
under each obfuscation:

| Obfuscation | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `base64` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 0.667 [0.510, 0.794] (26/39) |
| `base64_twice` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 0.545 [0.380, 0.702] (18/33) |
| `css_hidden` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.901, 1.000] (35/35) |
| `fullwidth` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.910, 1.000] (39/39) |
| `hex` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.883, 1.000] (29/29) |
| `homoglyph_cyrillic` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.914, 1.000] (41/41) | 0.812 [0.647, 0.911] (26/32) |
| `html_comment` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.898, 1.000] (34/34) |
| `html_entities` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.898, 1.000] (34/34) |
| `leetspeak` | 0.000 [0.000, 0.110] (0/31) | 0.829 [0.687, 0.915] (34/41) | 0.767 [0.591, 0.882] (23/30) |
| `letter_spaced` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.906, 1.000] (37/37) |
| `one_char_per_line` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.875, 1.000] (27/27) |
| `quoted_printable` | 0.000 [0.000, 0.110] (0/31) | 0.976 [0.877, 0.996] (41/42) | 0.958 [0.798, 0.993] (23/24) |
| `reversed` | 0.000 [0.000, 0.110] (0/31) | 0.952 [0.842, 0.987] (40/42) | 0.432 [0.287, 0.591] (16/37) |
| `rot13` | 0.000 [0.000, 0.110] (0/31) | 0.976 [0.874, 0.996] (40/41) | 0.000 [0.000, 0.102] (0/34) |
| `soft_hyphen_split` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.886, 1.000] (30/30) |
| `tag_smuggled` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 0.000 [0.000, 0.121] (0/28) |
| `typos` | 0.065 [0.018, 0.207] (2/31) | 0.857 [0.722, 0.933] (36/42) | 1.000 [0.898, 1.000] (34/34) |
| `unicode_escapes` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.898, 1.000] (34/34) |
| `url_encoded` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.890, 1.000] (31/31) |
| `url_query` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 1.000 [0.898, 1.000] (34/34) |
| `variation_selector_smuggled` | 0.000 [0.000, 0.110] (0/31) | 1.000 [0.916, 1.000] (42/42) | 0.000 [0.000, 0.094] (0/37) |
| `zero_width_split` | 1.000 [0.890, 1.000] (31/31) | 1.000 [0.916, 1.000] (42/42) | 0.903 [0.751, 0.967] (28/31) |

The earlier scanner lost every payload under nine of the 22 obfuscations. The
scanner now keeps at least 0.83 under each. The classifier loses all of them
when the payload is hidden in Unicode tag characters or variation selectors or
written in ROT13, which is the tokenizer blind spot
[Hackett et al. 2025](https://arxiv.org/abs/2504.11168) describe; any model
added later should be given text that the canonicaliser has already read.

The obfuscations were written alongside the code that undoes them, so these
figures show that the decoders work on other payloads, not that an attacker
has no encoding left. An obfuscation not in the set is not measured.

### By language

| Language | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `de` | 0.000 [0.000, 0.049] (0/75) | 0.147 [0.084, 0.244] (11/75) | 0.867 [0.772, 0.926] (65/75) |
| `en` | 0.160 [0.123, 0.204] (50/313) | 0.320 [0.270, 0.373] (100/313) | 0.885 [0.845, 0.916] (277/313) |
| `es` | 0.042 [0.011, 0.140] (2/48) | 0.229 [0.133, 0.365] (11/48) | 1.000 [0.926, 1.000] (48/48) |
| `fr` | 0.000 [0.000, 0.061] (0/59) | 0.390 [0.276, 0.517] (23/59) | 1.000 [0.939, 1.000] (59/59) |
| `it` | 0.000 [0.000, 0.058] (0/62) | 0.226 [0.140, 0.344] (14/62) | 1.000 [0.942, 1.000] (62/62) |
| `pt` | 0.000 [0.000, 0.056] (0/65) | 0.231 [0.145, 0.346] (15/65) | 0.985 [0.918, 0.997] (64/65) |
| `ro` | n<5 (0/3) | n<5 (0/3) | n<5 (3/3) |
| `undecided` | 0.018 [0.003, 0.095] (1/56) | 0.250 [0.155, 0.377] (14/56) | 0.911 [0.807, 0.961] (51/56) |

Recall outside English went from nothing to between 0.15 and 0.39. The rules
for these languages were written without review by a fluent reader, the
language bucket is a heuristic, and both sources are European. **There is no
public attack data here for Russian, Chinese, Japanese or Arabic**, so the
rules for those languages are covered only by their own examples.

### BIPIA

| Marker | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `names_the_answer` | 0.000 [0.000, 0.025] (0/147) | 0.286 [0.219, 0.363] (42/147) | 0.360 [0.287, 0.441] (53/147) |
| `none` | 0.000 [0.000, 0.017] (0/227) | 0.000 [0.000, 0.017] (0/227) | 0.110 [0.076, 0.158] (25/227) |

Most BIPIA attack strings are an ordinary request ("What is the capital of
Brazil?") placed in an email. Nothing in such a string says it is addressed to
the model, and a content scanner cannot tell it from the email. The scanner
finds none of those. It finds 0.286 of the strings that name the answer they
want changed ("…in your response").

### False positives

| Source | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `bipia` | 0.000 [0.000, 0.030] (0/125) | 0.000 [0.000, 0.030] (0/125) | 0.216 [0.153, 0.296] (27/125) |
| `deepset` | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) |
| `django_docs` | 0.000 [0.000, 0.003] (0/1207) | 0.000 [0.000, 0.003] (0/1207) | 0.045 [0.026, 0.076] (12/269) |
| `owasp_cheatsheets` | 0.017 [0.009, 0.032] (10/576) | 0.019 [0.011, 0.034] (11/576) | 0.056 [0.024, 0.125] (5/89) |
| `prompt_guide` | 0.026 [0.011, 0.059] (5/192) | 0.047 [0.025, 0.087] (9/192) | 0.091 [0.031, 0.236] (3/33) |
| `runbooks_openshift` | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.014] (0/267) | 0.000 [0.000, 0.047] (0/78) |
| `runbooks_prometheus` | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.064] (0/56) | 0.000 [0.000, 0.324] (0/8) |
| `wikipedia_ar` | 0.000 [0.000, 0.011] (0/331) | 0.000 [0.000, 0.011] (0/331) | 0.571 [0.441, 0.692] (32/56) |
| `wikipedia_de` | 0.000 [0.000, 0.010] (0/390) | 0.000 [0.000, 0.010] (0/390) | 0.127 [0.066, 0.231] (8/63) |
| `wikipedia_en` | 0.000 [0.000, 0.003] (0/1159) | 0.000 [0.000, 0.003] (0/1159) | 0.011 [0.004, 0.028] (4/363) |
| `wikipedia_es` | 0.000 [0.000, 0.011] (0/346) | 0.000 [0.000, 0.011] (0/346) | 0.045 [0.016, 0.125] (3/66) |
| `wikipedia_fa` | 0.000 [0.000, 0.014] (0/271) | 0.000 [0.000, 0.014] (0/271) | 0.256 [0.146, 0.411] (10/39) |
| `wikipedia_fr` | 0.000 [0.000, 0.011] (0/337) | 0.000 [0.000, 0.011] (0/337) | 0.077 [0.030, 0.182] (4/52) |
| `wikipedia_he` | 0.000 [0.000, 0.011] (0/359) | 0.000 [0.000, 0.011] (0/359) | 0.934 [0.843, 0.974] (57/61) |
| `wikipedia_ja` | 0.000 [0.000, 0.011] (0/329) | 0.000 [0.000, 0.011] (0/329) | 0.211 [0.122, 0.340] (11/52) |
| `wikipedia_ru` | 0.000 [0.000, 0.010] (0/395) | 0.000 [0.000, 0.010] (0/395) | 0.016 [0.003, 0.085] (1/63) |
| `wikipedia_zh` | 0.000 [0.000, 0.016] (0/240) | 0.000 [0.000, 0.016] (0/240) | 0.250 [0.138, 0.411] (9/36) |

All 20 of the scanner's false positives are in the OWASP cheat sheets and the
prompt-engineering guide, which describe injection attacks and quote them.
Thirteen of the 20 were marked `suspicious` (the text discusses attacks and
the match reads as a quotation) and are reported at medium severity and never
blocked. Whether these are false positives at all is arguable: a quoted
payload retrieved into a prompt can act on the model reading it. They are
counted as false positives here.

## Results on held-out sources

| Detector | Recall | False-positive rate | Recall at FPR ≤ 0.1% | Recall at FPR ≤ 1% |
|---|---|---|---|---|
| Scanner before this work | 0.246 [0.235, 0.258] (1380/5608) | 0.022 [0.012, 0.039] (11/499) | 0.000 (threshold 1.01, FPR 0.0) | 0.244 (threshold 0.6, FPR 0.002) |
| Scanner now | 0.264 [0.252, 0.275] (1478/5608) | 0.022 [0.012, 0.039] (11/499) | 0.000 (threshold 1.01, FPR 0.0) | 0.259 (threshold 0.6, FPR 0.002) |
| ProtectAI DeBERTa v2 | 0.645 [0.630, 0.660] (2580/4000) | 0.291 [0.253, 0.332] (145/499) | 0.000 (threshold 1.01, FPR 0.0) | 0.009 (threshold 1.0, FPR 0.00802) |

| Family / source | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `injecagent_base/injecagent` | 0.000 [0.000, 0.004] (0/1054) | 0.000 [0.000, 0.004] (0/1054) | 0.660 [0.630, 0.689] (660/1000) |
| `injecagent_enhanced/injecagent` | 1.000 [0.996, 1.000] (1054/1054) | 1.000 [0.996, 1.000] (1054/1054) | 1.000 [0.996, 1.000] (1000/1000) |
| `llmail_attempt/llmail` | 0.087 [0.075, 0.100] (174/2000) | 0.101 [0.088, 0.115] (202/2000) | 0.522 [0.491, 0.553] (522/1000) |
| `llmail_succeeded/llmail` | 0.101 [0.087, 0.118] (152/1500) | 0.148 [0.131, 0.167] (222/1500) | 0.398 [0.368, 0.429] (398/1000) |

- **InjecAgent, enhanced**: every row is found by both scanners, because the
  benchmark's "enhanced" setting prefixes the attacker's text with "IMPORTANT!!!
  Ignore all previous instructions…". This one family is 1,054 of the 1,478
  held-out rows the scanner finds.
- **InjecAgent, base**: none found. The attacker text is a plain request inside
  a tool response ("Please grant permanent access to my friend…"). Same limit
  as BIPIA.
- **LLMail-Inject**: 0.101 of judged attempts and 0.148 of the attacks that
  reached the tool call. These were written by people iterating against
  deployed injection detectors; they are what an adaptive attacker produces.

| Trigger words | Scanner before this work | Scanner now | ProtectAI DeBERTa v2 |
|---|---|---|---|
| `one` | 0.018 [0.005, 0.062] (2/113) | 0.018 [0.005, 0.062] (2/113) | 0.221 [0.155, 0.306] (25/113) |
| `three` | 0.053 [0.025, 0.111] (6/113) | 0.053 [0.025, 0.111] (6/113) | 0.540 [0.448, 0.629] (61/113) |
| `two` | 0.026 [0.009, 0.075] (3/113) | 0.026 [0.009, 0.075] (3/113) | 0.522 [0.431, 0.612] (59/113) |

NotInject's 339 benign sentences are built to contain words such as "ignore"
and "uncensored". The scanner flags 11 (0.032), unchanged from before. The
classifier flags 145 (0.428). None of the three detectors flags any of the 160
benign emails.

## Which rules did the work

On the test and held-out rows together, for each rule that can flag on its own:
how often it fired on attack rows and on benign rows.

| Rule | Fired on attacks | Fired on benign | Precision on this mix | Benign fire rate |
|---|---|---|---|---|
| `override.previous_instructions` | 1944 | 8 | 0.996 [0.992, 0.998] (1944/1952) | 0.001 [0.001, 0.002] (8/7135) |
| `override.all_instructions` | 1577 | 5 | 0.997 [0.993, 0.999] (1577/1582) | 0.001 [0.000, 0.002] (5/7135) |
| `delimiter.chat_tokens` | 207 | 19 | 0.916 [0.872, 0.946] (207/226) | 0.003 [0.002, 0.004] (19/7135) |
| `impersonation.tagged_turn` | 194 | 1 | 0.995 [0.972, 0.999] (194/195) | 0.000 [0.000, 0.001] (1/7135) |
| `override.abandon_your_rules` | 144 | 0 | 1.000 [0.974, 1.000] (144/144) | 0.000 [0.000, 0.001] (0/7135) |
| `override.your_instructions` | 134 | 0 | 1.000 [0.972, 1.000] (134/134) | 0.000 [0.000, 0.001] (0/7135) |
| `override.previous_directions` | 107 | 6 | 0.947 [0.889, 0.975] (107/113) | 0.001 [0.000, 0.002] (6/7135) |
| `hidden.markup` | 104 | 0 | 1.000 [0.964, 1.000] (104/104) | 0.000 [0.000, 0.001] (0/7135) |
| `exfil.repeat_instructions` | 96 | 4 | 0.960 [0.902, 0.984] (96/100) | 0.001 [0.000, 0.001] (4/7135) |
| `override.new_instructions` | 90 | 0 | 1.000 [0.959, 1.000] (90/90) | 0.000 [0.000, 0.001] (0/7135) |
| `response.in_your_answer` | 85 | 1 | 0.988 [0.937, 0.998] (85/86) | 0.000 [0.000, 0.001] (1/7135) |
| `override.your_new_task` | 41 | 0 | 1.000 [0.914, 1.000] (41/41) | 0.000 [0.000, 0.001] (0/7135) |
| `exfil.reveal_prompt` | 30 | 3 | 0.909 [0.764, 0.969] (30/33) | 0.000 [0.000, 0.001] (3/7135) |
| `fr.override` | 27 | 0 | 1.000 [0.875, 1.000] (27/27) | 0.000 [0.000, 0.001] (0/7135) |
| `override.romance_verbs` | 26 | 0 | 1.000 [0.871, 1.000] (26/26) | 0.000 [0.000, 0.001] (0/7135) |
| `override.what_you_were_told` | 26 | 0 | 1.000 [0.871, 1.000] (26/26) | 0.000 [0.000, 0.001] (0/7135) |
| `override.original_instructions` | 25 | 2 | 0.926 [0.766, 0.979] (25/27) | 0.000 [0.000, 0.001] (2/7135) |
| `ru.override` | 19 | 0 | 1.000 [0.832, 1.000] (19/19) | 0.000 [0.000, 0.001] (0/7135) |
| `es.reveal_prompt` | 18 | 0 | 1.000 [0.824, 1.000] (18/18) | 0.000 [0.000, 0.001] (0/7135) |
| `fr.reveal_prompt` | 18 | 0 | 1.000 [0.824, 1.000] (18/18) | 0.000 [0.000, 0.001] (0/7135) |
| `it.reveal_prompt` | 18 | 0 | 1.000 [0.824, 1.000] (18/18) | 0.000 [0.000, 0.001] (0/7135) |
| `pt.reveal_prompt` | 18 | 0 | 1.000 [0.824, 1.000] (18/18) | 0.000 [0.000, 0.001] (0/7135) |
| `de.override` | 16 | 0 | 1.000 [0.806, 1.000] (16/16) | 0.000 [0.000, 0.001] (0/7135) |
| `fr.obey_only_me` | 16 | 0 | 1.000 [0.806, 1.000] (16/16) | 0.000 [0.000, 0.001] (0/7135) |
| `es.override` | 14 | 0 | 1.000 [0.785, 1.000] (14/14) | 0.000 [0.000, 0.001] (0/7135) |
| `it.override` | 13 | 0 | 1.000 [0.772, 1.000] (13/13) | 0.000 [0.000, 0.001] (0/7135) |
| `pt.override` | 13 | 0 | 1.000 [0.772, 1.000] (13/13) | 0.000 [0.000, 0.001] (0/7135) |
| `it.obey_only_me` | 11 | 0 | 1.000 [0.741, 1.000] (11/11) | 0.000 [0.000, 0.001] (0/7135) |
| `de.reveal_prompt` | 6 | 0 | 1.000 [0.610, 1.000] (6/6) | 0.000 [0.000, 0.001] (0/7135) |
| `override.forget_everything` | 6 | 0 | 1.000 [0.610, 1.000] (6/6) | 0.000 [0.000, 0.001] (0/7135) |
| `retrieval.ignore_context` | 6 | 0 | 1.000 [0.610, 1.000] (6/6) | 0.000 [0.000, 0.001] (0/7135) |
| `ja.override` | 4 | 0 | n<5 (4/4) | 0.000 [0.000, 0.001] (0/7135) |
| `override.obey_only_me` | 4 | 0 | n<5 (4/4) | 0.000 [0.000, 0.001] (0/7135) |
| `addressing.note_to_ai` | 2 | 0 | n<5 (2/2) | 0.000 [0.000, 0.001] (0/7135) |
| `exfil.what_are_your_instructions` | 2 | 1 | n<5 (2/3) | 0.000 [0.000, 0.001] (1/7135) |
| `role.enter_mode` | 2 | 1 | n<5 (2/3) | 0.000 [0.000, 0.001] (1/7135) |
| `tool.call_syntax` | 2 | 1 | n<5 (2/3) | 0.000 [0.000, 0.001] (1/7135) |
| `bypass.safety` | 1 | 11 | 0.083 [0.015, 0.354] (1/12) | 0.002 [0.001, 0.003] (11/7135) |
| `role.pretend` | 1 | 5 | 0.167 [0.030, 0.564] (1/6) | 0.001 [0.000, 0.002] (5/7135) |
| `role.you_are_now` | 1 | 2 | n<5 (1/3) | 0.000 [0.000, 0.001] (2/7135) |
| `override.do_not_mention` | 0 | 1 | n<5 (0/1) | 0.000 [0.000, 0.001] (1/7135) |
| `role.in_mode` | 0 | 1 | n<5 (0/1) | 0.000 [0.000, 0.001] (1/7135) |
| `role.named_mode` | 0 | 2 | n<5 (0/2) | 0.000 [0.000, 0.001] (2/7135) |

Two things in this table are worth acting on, and neither was acted on here,
because changing a rule in response to held-out rows would spend the held-out
split:

- `bypass.safety` and `role.pretend`, both from the earlier scanner, fired
  more often on benign rows than on attacks. They account for most of the
  NotInject false positives and are candidates to become supporting rules.
- Most rules fired on no benign row at all. With 7,135 benign rows that bounds
  each one's benign fire rate at about 0.001 at best, which is not enough to
  call any rule `likely` in the sense the action gates need. Per-rule
  confidence classes need a larger benign set.

## What this means for a classifier layer

The decision taken for the next phase is to adopt a pre-trained model, not
train one. This benchmark says what a pre-trained model has to be wrapped in
before it is useful on a corpus:

- **Language gating.** The model is English-only and flags most Hebrew and
  Arabic text. It should run only on text detected as English.
- **A threshold near saturation.** At 0.5 it flags 15% of documents. Its
  scores pile up at 1.0, so the usable operating point is a threshold above
  0.999, where its recall on the test split is 0.47 at a 1% false-positive
  rate.
- **Short windows.** It is twice as good on a 500-character document as on a
  2,000-character one. Sentence- or paragraph-level windows suit it better
  than whole chunks.
- **Canonicalised input.** It reads nothing in tag characters, variation
  selectors or ROT13.
- **A second opinion, not a verdict.** On held-out data at a 1% false-positive
  rate it finds 0.009. On NotInject it is wrong 43% of the time. It adds
  recall on paraphrase (0.973 on the yanismiraoui prompts against the
  scanner's 0.214) and should be used to raise a chunk for review, not to
  block or delete.

Other pre-trained models were not scored. Meta's Prompt Guard 2 is gated under
a licence that does not fit this project's distribution; PIGuard needs
`trust_remote_code`. Both can be scored through the same adapter by someone
licensed to download them.

## Speed

One process, one core, Apple M4 Pro, Python 3.12.13, 33.4 million characters:

| Detector | Wall time | ms per 1,000 characters | Slowest row |
|---|---|---|---|
| Scanner before (first 5,000 characters only) | 25.2 s | 0.76 | 46 ms |
| Scanner now (whole text) | 36.1 s | 1.08 | 36 ms |
| ProtectAI DeBERTa v2 (9.1 million characters) | 500.6 s | 55.2 | 793 ms |

Inputs built to make a pattern backtrack (200,000 characters each of repeated
`<a style='`, `![`, `<!--`, and others) take between 36 and 530 ms with the
scanner now; the unit tests run them inside the 2-second budget.

## What this benchmark does not show

- **Recall against an attacker who is trying.** Apart from LLMail-Inject, the
  attacks are static strings. Published adaptive attacks defeat every detector
  tested against them ([Nasr et al. 2025](https://arxiv.org/abs/2510.09023)).
- **Knowledge poisoning.** A false statement with no instruction in it is not
  in this dataset and is not what the scanner looks for.
- **Non-European languages**, as above.
- **False positives on your documents.** The benign set is 13,880 rows. It
  has no chat transcripts, tickets, contracts or source code, and the sources that discuss attacks are where every false positive
  was. A corpus of security or prompt-engineering material will see more.
- **Span accuracy.** Whether a match's character span covers the payload was
  not scored.
- **Label quality.** deepset's labels are known to be noisy (role-play prompts
  marked as injections). They are used as published.
- **The classifier beyond a sample.** It was scored on 8,777 of 15,889 test and
  held-out rows.
- **A committed revision.** The scanner code was an uncommitted working tree
  on top of `0041576` when these runs were made. Re-run after the change is
  committed and compare against the recorded summaries.

## Reproduce

```bash
pip install -e . -r benchmarks/injection/requirements.txt
python benchmarks/injection/fetch.py
python benchmarks/injection/build.py     # prints the dataset sha256
python benchmarks/injection/run.py --detectors legacy vecshield
python benchmarks/injection/report.py
```

`fetch.py` fails if any downloaded file differs from `sources.lock.json`.
`build.py` prints the dataset hash; it should match
`recorded/2026-11-18-dataset-manifest.json`. This benchmark is not yet a CI
gate: it was run by hand, and the figures above are the recorded output of
that run.
