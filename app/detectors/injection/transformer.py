"""Layer-2 transformer prompt-injection detector — WARN mode.

This is the model selected in [ADR-014] and fine-tuned in [ADR-015], integrated at
last under [ADR-021]. It runs **warn-only**: it records evidence and never blocks.
Promotion to blocking is a separate decision (OD-18) that needs shadow-mode
false-positive data from real traffic, which is precisely what running this
detector produces.

**It ships disabled.** A default install has no `[ml]` extra and no checkpoint on
disk, and the default policy leaves `enabled: false`, so behaviour is unchanged
until an operator opts in. Enabling it without the dependencies or the weights is
a configuration error raised at **startup**, not a 503 per request: a security
control that cannot load should stop a deployment, not degrade one.

**No weights live in this tree.** `model_path` must point outside `app/`; the
checkpoint stays in `artifacts/` (gitignored) and never enters the container
image. `tests/unit/test_transformer_detector.py` asserts both.

Scores are the model's softmax probability for the INJECTION class. They are
comparable only against this detector's own threshold — 0.9955 for the Strategy A
checkpoint, frozen in its selection lock before the hold-out was scored and not
re-tuned here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.config.policy import DetectorPolicy
from app.core.exceptions import ConfigurationError
from app.core.types import Category, DetectionContext, DetectionResult, Direction
from app.detectors.base import SyncDetectorAdapter

# The window the model was trained and evaluated at (ADR-015). Text beyond it is
# truncated and therefore *unseen*, which is a detection gap rather than a
# performance detail — so it is reported on every result that hits it.
MAX_LENGTH = 512

# Strategy A's locked operating point. Recorded here so a policy that omits a
# threshold cannot silently fall back to the unrelated 0.85 heuristic default.
DEFAULT_THRESHOLD = 0.9955


class TransformerInjectionDetector(SyncDetectorAdapter):
    """DeBERTa-v3 sequence classifier, `{0: SAFE, 1: INJECTION}`.

    Synchronous and CPU-bound, so it runs through `SyncDetectorAdapter`'s bounded
    thread offload rather than on the event loop.
    """

    name = "injection.transformer"
    category = Category.PROMPT_INJECTION
    directions = frozenset({Direction.INPUT})
    emits_spans = False
    # The fine-tuned checkpoint was trained and evaluated without provenance
    # (ADR-015). Provenance-aware scoring is a separate arm (ADR-018) and is not
    # claimed here.
    consumes_provenance = False

    def __init__(self, policy: DetectorPolicy | None = None, **kwargs: Any) -> None:
        super().__init__(policy, **kwargs)
        options = dict(policy.options) if policy else {}
        raw_path = options.get("model_path")
        self._model_path = Path(str(raw_path)).expanduser() if raw_path else None
        self._device = str(options.get("device", "cpu"))
        self._model: Any | None = None
        self._tokenizer: Any | None = None

    @property
    def threshold(self) -> float:
        return self.policy.threshold if self.policy else DEFAULT_THRESHOLD

    async def warmup(self) -> None:
        """Load the checkpoint once, at startup.

        Model loading costs seconds. Paying it on the first request would make
        that request an outlier and hide the cost from every benchmark.
        """
        if self._model is not None:
            return
        if self._model_path is None:
            raise ConfigurationError(
                f"{self.name} is enabled but no options.model_path is configured. "
                "Point it at a checkpoint outside the application tree, or disable "
                "the detector."
            )
        if not (self._model_path / "config.json").is_file():
            raise ConfigurationError(
                f"{self.name}: no model at {self._model_path}. The checkpoint is not "
                "committed to this repository (docs/14-dataset-strategy.md); fetch or "
                "train it, or disable the detector."
            )
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ConfigurationError(
                f"{self.name} is enabled but the 'ml' extra is not installed. "
                "Install it (uv sync --extra ml) or disable the detector."
            ) from exc

        self._tokenizer = AutoTokenizer.from_pretrained(str(self._model_path))
        model = AutoModelForSequenceClassification.from_pretrained(str(self._model_path))
        model.eval()
        self._model = model.to(self._device)

    async def aclose(self) -> None:
        self._model = None
        self._tokenizer = None

    def detect_sync(self, ctx: DetectionContext) -> DetectionResult:
        if self._model is None or self._tokenizer is None:
            raise ConfigurationError(f"{self.name}.warmup() was not called before detect()")

        import torch

        encoded = self._tokenizer(
            ctx.normalized_text,
            truncation=True,
            max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        token_count = int(encoded["input_ids"].shape[1])
        truncated = token_count >= MAX_LENGTH
        encoded = {k: v.to(self._device) for k, v in encoded.items()}

        with torch.no_grad():
            logits = self._model(**encoded).logits
        score = float(torch.softmax(logits, dim=-1)[0, 1].item())

        detected = score >= self.threshold
        reasons: tuple[str, ...] = ()
        if detected:
            # No content, no matched text, no rule name — the score and the
            # category are the whole finding (docs/10-security-model.md).
            reasons = ("transformer_classifier_positive",)
        if truncated:
            reasons += ("input_truncated_to_model_window",)

        return self._result(
            detected=detected,
            score=score,
            reasons=reasons,
            metadata={
                "model": "deberta-v3-base-prompt-injection-v2 (fine-tuned, ADR-015)",
                "threshold": self.threshold,
                "calibrated": True,
                "baseline": False,
                "mode": "warn_only",
                "tokens": token_count,
                "truncated": truncated,
                "device": self._device,
            },
        )


def build(policy: DetectorPolicy) -> TransformerInjectionDetector:
    return TransformerInjectionDetector(policy)
