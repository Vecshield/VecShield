"""Detectors under test, each ``text -> (flagged, score)``.

``legacy``       the scanner as it stood before this work, loaded from a pinned
                 commit and called the way the integrity engine called it
                 (first 5,000 characters of a surface)
``vecshield``    the current scanner, whole text
``protectai_v2`` a pre-trained classifier baseline (optional; needs
                 onnxruntime and tokenizers and a local copy of the model)
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[2]

#: The last commit before the scanner was changed.
LEGACY_COMMIT = "0041576"
LEGACY_PATH = "vecshield_platform/integrity/injection.py"

Detector = Callable[[str], tuple]


def legacy() -> Detector:
    source = subprocess.run(["git", "-C", str(REPO), "show", f"{LEGACY_COMMIT}:{LEGACY_PATH}"],
                            check=True, capture_output=True, text=True).stdout
    module = types.ModuleType("legacy_injection")
    sys.modules[module.__name__] = module
    exec(compile(source, f"{LEGACY_COMMIT}:{LEGACY_PATH}", "exec"), module.__dict__)  # noqa: S102

    def detect(text: str) -> tuple[bool, float]:
        result = module.scan_text(text[:5000])
        return bool(result.is_injection), float(result.score)

    return detect


def vecshield() -> Detector:
    from vecshield.injection import scan_text

    def detect(text: str) -> tuple:
        result = scan_text(text)
        return bool(result.is_injection), float(result.score), {
            "rules": result.rules, "verdict": result.verdict,
            "primary": [s["rule"] for s in result.spans if s["weight"] > 0.3]}

    return detect


def protectai_v2(model_dir: str, *, threshold: float = 0.5, max_windows: int = 8) -> Detector:
    """``protectai/deberta-v3-base-prompt-injection-v2`` through ONNX Runtime.

    512-token windows with a 64-token overlap, the maximum injection
    probability over the first ``max_windows`` windows.
    """
    import numpy as np
    import onnxruntime as ort
    from tokenizers import Tokenizer

    root = Path(model_dir)
    tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    session = ort.InferenceSession(str(root / "model.onnx"),
                                   providers=["CPUExecutionProvider"])
    inputs = {i.name for i in session.get_inputs()}
    cls, sep = tokenizer.token_to_id("[CLS]"), tokenizer.token_to_id("[SEP]")
    body, stride = 510, 446

    def detect(text: str) -> tuple[bool, float]:
        ids = tokenizer.encode(text, add_special_tokens=False).ids
        best = 0.0
        for window, start in enumerate(range(0, max(len(ids), 1), stride)):
            if window >= max_windows:
                break
            piece = [cls] + ids[start:start + body] + [sep]
            feed = {"input_ids": np.array([piece], dtype=np.int64),
                    "attention_mask": np.ones((1, len(piece)), dtype=np.int64)}
            if "token_type_ids" in inputs:
                feed["token_type_ids"] = np.zeros((1, len(piece)), dtype=np.int64)
            logits = session.run(None, feed)[0][0]
            exp = np.exp(logits - logits.max())
            best = max(best, float(exp[1] / exp.sum()))
            if start + body >= len(ids):
                break
        return best >= threshold, best

    return detect


#: Pre-trained classifiers scored as candidates for the classifier layer.
#: ``file`` is relative to the model directory the caller supplies. ``window``
#: and ``stride`` are in tokens. Each is Apache-2.0, not gated, and loads
#: without custom code. ``trained_on`` lists this benchmark's sources that the
#: model's card names as training data, so a score on them is not out of
#: sample; a source the card does not mention is "not stated", not "unseen".
CLASSIFIERS = {
    "protectai_v2": {"repo": "protectai/deberta-v3-base-prompt-injection-v2",
                     "file": "model.onnx", "window": 510, "stride": 446, "special": True,
                     "trained_on": ()},
    "horizon_small": {"repo": "Horizon-Labs/prompt-injection-guard-small",
                      "file": "model_quantized.onnx", "window": 2046, "stride": 1982,
                      "special": True,
                      "trained_on": ("slabs", "wambosec", "gandalf", "yanismiraoui",
                                     "deepset", "jailbreak")},
    "horizon_base": {"repo": "Horizon-Labs/prompt-injection-guard-base",
                     "file": "model_quantized.onnx", "window": 2046, "stride": 1982,
                     "special": True,
                     "trained_on": ("slabs", "wambosec", "gandalf", "yanismiraoui",
                                    "deepset", "jailbreak")},
    "wolf_small": {"repo": "patronus-studio/wolf-defender-prompt-injection-small",
                   "file": "model_mixed.onnx", "window": 2046, "stride": 1982,
                   "special": True, "trained_on": ("deepset", "llmail")},
    "wolf_base": {"repo": "patronus-studio/wolf-defender-prompt-injection",
                  "file": "model_mixed.onnx", "window": 2046, "stride": 1982,
                  "special": True, "trained_on": ("deepset", "llmail")},
}


def onnx_classifier(name: str, model_dir: str, *, threshold: float = 0.5,
                    max_windows: int = 8, canonical: bool = False) -> Detector:
    """A pre-trained sequence classifier through ONNX Runtime, max over windows.

    Label 1 is the injection class for every model listed. ``canonical`` feeds
    the model the scanner's normalised reading of the text instead of the raw
    text. Windowing follows each model's card; pooling is the maximum, which is
    what Horizon documents and a simplification of Wolf's smooth-max.
    """
    import numpy as np
    import onnxruntime as ort
    from tokenizers import Tokenizer

    spec = CLASSIFIERS[name]
    root = Path(model_dir)
    tokenizer = Tokenizer.from_file(str(root / "tokenizer.json"))
    tokenizer.no_truncation()
    tokenizer.no_padding()
    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    session = ort.InferenceSession(str(root / spec["file"]), sess_options=options,
                                   providers=["CPUExecutionProvider"])
    inputs = {i.name for i in session.get_inputs()}
    probe = tokenizer.encode("x", add_special_tokens=True).ids
    head, tail = probe[:1], probe[-1:]
    body, stride = spec["window"], spec["stride"]

    def detect(text: str) -> tuple:
        if canonical:
            from vecshield.injection import canonical as views

            text = views.fold_confusables(views.normalize(views.decode_tag_characters(text))[0])
        ids = tokenizer.encode(text, add_special_tokens=False).ids
        best = 0.0
        for window, start in enumerate(range(0, max(len(ids), 1), stride)):
            if window >= max_windows:
                break
            piece = head + ids[start:start + body] + tail
            feed = {"input_ids": np.array([piece], dtype=np.int64),
                    "attention_mask": np.ones((1, len(piece)), dtype=np.int64)}
            if "token_type_ids" in inputs:
                feed["token_type_ids"] = np.zeros((1, len(piece)), dtype=np.int64)
            logits = session.run(None, feed)[0][0].astype(np.float64)
            exp = np.exp(logits - logits.max())
            best = max(best, float(exp[1] / exp.sum()))
            if start + body >= len(ids):
                break
        return best >= threshold, best

    return detect
