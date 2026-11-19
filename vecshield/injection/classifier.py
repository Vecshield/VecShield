"""An optional pre-trained classifier, as a second opinion beside the rules.

The rules read signatures. A pre-trained classifier reads phrasing, so it finds
instructions the rules have no signature for: paraphrases, other languages,
social engineering. It is also wrong more often on ordinary text, costs tens of
milliseconds per thousand characters, and is a file of weights somebody else
trained. So it is optional, it is never the sole reason to block anything, and
this module is strict about what it will load:

* **Nothing is downloaded.** The operator puts the model files in a directory
  and points ``VECSHIELD_INJECTION_MODEL_DIR`` at it (or passes a loaded
  classifier to ``scan_text``).
* **The files are pinned.** A model is loaded only if the SHA-256 of its ONNX
  file and tokenizer match an entry in :data:`CATALOG`, or hashes the caller
  supplies. A file that does not match is refused, not warned about.
* **Only data is loaded.** One ONNX graph and one tokenizer JSON, through
  ``onnxruntime`` and ``tokenizers``. No pickle, no repository code, no
  ``trust_remote_code``, no PyTorch.
* **It reads what the rules read.** The classifier is given the canonical
  reading of the text, because a model cannot see an instruction hidden in
  characters its tokenizer drops.

The models in the catalogue are Apache-2.0, ungated, and were scored on this
project's benchmark; see ``docs/library/benchmarks/injection.md`` for what each
found, what it got wrong, and which benchmark sources it had been trained on.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

MODEL_DIR_ENV = "VECSHIELD_INJECTION_MODEL_DIR"
MODEL_NAME_ENV = "VECSHIELD_INJECTION_MODEL"
THRESHOLD_ENV = "VECSHIELD_INJECTION_MODEL_THRESHOLD"

#: Token windows scored per text. A longer text is scored up to here and the
#: result says the classifier did not read all of it.
MAX_WINDOWS = 8


class ClassifierUnavailable(RuntimeError):
    """The classifier was asked for and could not be loaded. Never a pass."""


@dataclass(frozen=True)
class ModelSpec:
    name: str
    repo: str
    revision: str
    licence: str
    onnx_file: str
    onnx_sha256: str
    tokenizer_sha256: str
    #: Tokens per window (without the two special tokens) and the step between windows.
    window: int
    stride: int
    #: ``None`` when the model is multilingual; otherwise the languages it was
    #: trained for. Text in another language is not sent to it.
    languages: Optional[tuple[str, ...]]
    #: Probability at or above which the classifier's opinion flags a text.
    #: Set from the benchmark's dev split for a false-positive rate of about
    #: one in a thousand on ordinary documents; see the benchmark write-up.
    threshold: float


#: Models this module will load by name. ``onnx_file`` is the file's name in
#: the operator's model directory; the repository path it came from is in the
#: installation notes (docs/library/injection_classifier.md).
CATALOG: dict[str, ModelSpec] = {}


def _register(spec: ModelSpec) -> None:
    CATALOG[spec.name] = spec


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class OnnxClassifier:
    """A pinned sequence classifier. ``score(text)`` is the injection probability."""

    def __init__(self, model_dir: str | os.PathLike, *, name: Optional[str] = None,
                 spec: Optional[ModelSpec] = None, threshold: Optional[float] = None,
                 threads: Optional[int] = None):
        root = Path(model_dir)
        if spec is None:
            spec = self._identify(root, name)
        self.spec = spec
        self.threshold = spec.threshold if threshold is None else float(threshold)
        if not 0.0 < self.threshold <= 1.0:
            raise ClassifierUnavailable("classifier threshold must be in (0, 1]")
        model_path, tokenizer_path = root / spec.onnx_file, root / "tokenizer.json"
        for path, expected, what in ((model_path, spec.onnx_sha256, "model"),
                                     (tokenizer_path, spec.tokenizer_sha256, "tokenizer")):
            if not path.is_file():
                raise ClassifierUnavailable(f"{what} file not found: {path.name}")
            actual = sha256_file(path)
            if actual != expected:
                raise ClassifierUnavailable(
                    f"{what} file {path.name} does not match the pinned SHA-256 for "
                    f"'{spec.name}' (expected {expected[:12]}…, found {actual[:12]}…); "
                    "refusing to load it")
        try:
            import numpy
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ClassifierUnavailable(
                "the classifier layer needs onnxruntime and tokenizers "
                "(pip install 'vecshield[injection-ml]')") from exc
        self._np = numpy
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        options = onnxruntime.SessionOptions()
        if threads:
            options.intra_op_num_threads = int(threads)
        # CPU only, and only the graph in this one verified file.
        self._session = onnxruntime.InferenceSession(
            str(model_path), sess_options=options, providers=["CPUExecutionProvider"])
        self._inputs = {i.name for i in self._session.get_inputs()}
        probe = self._tokenizer.encode("x", add_special_tokens=True).ids
        self._head, self._tail = probe[:1], probe[-1:]

    @staticmethod
    def _identify(root: Path, name: Optional[str]) -> ModelSpec:
        if name:
            if name not in CATALOG:
                raise ClassifierUnavailable(
                    f"unknown classifier '{name}'; known: {', '.join(sorted(CATALOG))}")
            return CATALOG[name]
        # No name given: the directory must hold exactly one catalogued model.
        present = [spec for spec in CATALOG.values() if (root / spec.onnx_file).is_file()]
        for spec in present:
            if sha256_file(root / spec.onnx_file) == spec.onnx_sha256:
                return spec
        raise ClassifierUnavailable(
            f"no catalogued model file found in {root.name!r}; set {MODEL_NAME_ENV} or "
            "see docs/library/injection_classifier.md")

    @property
    def name(self) -> str:
        return self.spec.name

    def reads(self, language: Optional[str]) -> bool:
        """Whether the model was trained for text in ``language`` (None: undecided)."""
        return self.spec.languages is None or language is None \
            or language in self.spec.languages

    def score(self, text: str) -> dict:
        """``{"probability", "span", "windows", "complete"}`` for one text.

        The probability is the highest over the windows; ``span`` is the
        character range of that window in ``text``.
        """
        np = self._np
        encoding = self._tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = encoding.ids, encoding.offsets
        best, best_span, windows, complete = 0.0, None, 0, True
        for index, start in enumerate(range(0, max(len(ids), 1), self.spec.stride)):
            if index >= MAX_WINDOWS:
                complete = False
                break
            piece = ids[start:start + self.spec.window]
            feed = {"input_ids": np.array([self._head + piece + self._tail], dtype=np.int64)}
            feed["attention_mask"] = np.ones_like(feed["input_ids"])
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = np.zeros_like(feed["input_ids"])
            logits = self._session.run(None, feed)[0][0].astype(np.float64)
            exp = np.exp(logits - logits.max())
            probability = float(exp[1] / exp.sum())
            windows += 1
            if probability > best and piece:
                best = probability
                best_span = (offsets[start][0], offsets[start + len(piece) - 1][1])
            if start + self.spec.window >= len(ids):
                break
        return {"probability": best, "span": best_span, "windows": windows,
                "complete": complete}


_default: Optional[OnnxClassifier] = None
_default_error: Optional[str] = None
_default_loaded = False


def default_classifier() -> tuple[Optional[OnnxClassifier], Optional[str]]:
    """The classifier configured in the environment, loaded once.

    Returns ``(classifier, None)``, ``(None, None)`` when none is configured,
    or ``(None, reason)`` when one is configured and could not be loaded. The
    last is reported as a layer that was asked for and did not run.
    """
    global _default, _default_error, _default_loaded
    if not _default_loaded:
        _default_loaded = True
        directory = (os.environ.get(MODEL_DIR_ENV) or "").strip()
        if directory:
            try:
                raw = (os.environ.get(THRESHOLD_ENV) or "").strip()
                _default = OnnxClassifier(
                    directory, name=(os.environ.get(MODEL_NAME_ENV) or "").strip() or None,
                    threshold=float(raw) if raw else None)
            except (ClassifierUnavailable, ValueError, OSError) as exc:
                _default_error = str(exc)
    return _default, _default_error


def reset_default_classifier() -> None:
    """Forget the environment's classifier, so the next call reads it again."""
    global _default, _default_error, _default_loaded
    _default, _default_error, _default_loaded = None, None, False


# --------------------------------------------------------------------------- #
# the catalogue                                                               #
# --------------------------------------------------------------------------- #
# Revisions and hashes are of the files as downloaded on 2026-11-18. The
# thresholds come from the benchmark's dev split (dataset 4bbe1ae7): the lowest
# probability at which each model flagged no more than one in a thousand of the
# dev split's ordinary documents. They are starting points for a corpus like
# that one, not guarantees; VECSHIELD_INJECTION_MODEL_THRESHOLD overrides them.

_register(ModelSpec(
    name="horizon-guard-small",
    repo="Horizon-Labs/prompt-injection-guard-small",
    revision="2efc2ed5abecd21eb45c2506d231a65d6e392b85",
    licence="Apache-2.0",
    onnx_file="model_quantized.onnx",
    onnx_sha256="61cd0741cdbfcc229e32e1de1392f352736d87d1e8b3c2b67ad9836bb7910d5d",
    tokenizer_sha256="47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46",
    window=2046, stride=1982, languages=None, threshold=0.925))

_register(ModelSpec(
    name="wolf-defender-small",
    repo="patronus-studio/wolf-defender-prompt-injection-small",
    revision="2484cc9a13550aa4f2c29b577ff3ef331dc6ba07",
    licence="Apache-2.0",
    onnx_file="model_mixed.onnx",
    onnx_sha256="b2b58b1219645e690f9703d98feabd23924e4828cd2f4f788efc933fffcc38ed",
    tokenizer_sha256="609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f",
    window=2046, stride=1982, languages=None, threshold=0.87))
