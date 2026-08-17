"""Candidate ML detectors, for evaluation only.

**Nothing here is wired into the gateway.** These adapters exist so candidates
can be measured on the same data, the same splits and the same machine as the
baseline before any production decision is made (docs/13-evaluation-strategy.md).
A candidate that wins here is integrated afterwards, behind the same
`app.detectors` protocol.

Two properties the adapters preserve so the comparison is fair:

* **Identical preprocessing.** Candidates receive the same normalised text the
  baseline sees, timed separately, so the comparison is of detection and not of
  tokeniser overhead hidden in different places.
* **Real inference cost.** Models are warmed before timing; first-call model
  loading is not counted as detection latency.

Model weights are downloaded on first use into the HuggingFace cache, never into
this repository. Every candidate records the licence and revision it was
measured at.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from eval.detectors import Prediction
from eval.schema import DETECTOR_SCOPE, Category, Sample


@dataclass(frozen=True, slots=True)
class CandidateSpec:
    """What was verified about a candidate, and where."""

    key: str
    hf_id: str
    licence: str
    gated: bool
    parameters: int
    task: str
    attack_label: str
    scope: frozenset[Category]
    verified_on: str
    notes: str
    max_length: int = 512


# Verified against the HuggingFace API on 2026-08-17 (licence tag, gated flag,
# parameter count from the safetensors metadata). Re-verify before relying on it.
CANDIDATES: dict[str, CandidateSpec] = {
    "injection.protectai_deberta_v2": CandidateSpec(
        key="injection.protectai_deberta_v2",
        hf_id="protectai/deberta-v3-base-prompt-injection-v2",
        licence="apache-2.0",
        gated=False,
        parameters=184_423_682,
        task="sequence-classification (binary)",
        attack_label="INJECTION",
        scope=DETECTOR_SCOPE["injection.heuristic"],
        verified_on="2026-08-17",
        notes=(
            "DeBERTa-v3-base fine-tuned for prompt injection. Apache-2.0 and ungated, "
            "so it is usable and locally benchmarkable. Trained on public injection "
            "corpora, so its numbers on deepset/gandalf are optimistically biased — "
            "which is exactly why the internal hold-out exists."
        ),
    ),
    "injection.arch_guard": CandidateSpec(
        key="injection.arch_guard",
        hf_id="katanemo/Arch-Guard",
        licence="mit",
        gated=False,
        parameters=278_811_651,
        task="sequence-classification (binary)",
        attack_label="JAILBREAK",
        scope=DETECTOR_SCOPE["injection.heuristic"],
        verified_on="2026-08-17",
        notes=(
            "MIT-licensed jailbreak/injection classifier. Ungated and locally "
            "benchmarkable. Its label vocabulary differs from ProtectAI's, so the "
            "positive class is resolved from the model config rather than assumed."
        ),
    ),
}

# Verified as unavailable for a reproducible, unauthenticated benchmark. Recorded
# so the decision is evidence-based and not re-litigated from memory.
NOT_LOCALLY_BENCHMARKABLE: dict[str, dict[str, Any]] = {
    "meta-llama/Prompt-Guard-86M": {
        "licence": "llama3.1",
        "gated": "manual",
        "reason": (
            "Gated behind manual approval, so it cannot be fetched by a reproducible "
            "script. The Llama licence also carries acceptable-use terms that need "
            "review before commercial deployment."
        ),
        "verified_on": "2026-08-17",
    },
    "meta-llama/Llama-Prompt-Guard-2-86M": {
        "licence": "other (Llama)",
        "gated": "manual",
        "reason": "Gated behind manual approval; same licence-review requirement.",
        "verified_on": "2026-08-17",
    },
    "meta-llama/Llama-Guard-3-1B": {
        "licence": "llama3.2",
        "gated": "manual",
        "reason": (
            "Gated, and at 1.5B parameters it is a generative safety classifier whose "
            "latency profile is an order of magnitude above an encoder classifier — a "
            "different architectural tier, evaluated only if the encoder tier proves "
            "insufficient."
        ),
        "verified_on": "2026-08-17",
    },
    "testsavantai/prompt-injection-defender-small-v0": {
        "licence": "none declared",
        "gated": False,
        "reason": (
            "No licence declared on the model repository. Unlicensed weights cannot be "
            "used in a project that must state its own licensing position."
        ),
        "verified_on": "2026-08-17",
    },
}


class TransformerCandidate:
    """Sequence-classification candidate driven through the same harness.

    Runs on CPU by default. The reference GPU has 4 GB, which fits a base-size
    encoder, but CPU is the honest default: it is what a container without a GPU
    would use, and mixing devices across candidates would make the latency
    comparison meaningless.
    """

    def __init__(self, spec: CandidateSpec, *, threshold: float = 0.5, device: str = "cpu"):
        self.spec = spec
        self.name = spec.key
        self._threshold = threshold
        self._device = device
        self._model: Any = None
        self._tokenizer: Any = None
        self._attack_index: int | None = None
        self._revision: str | None = None

    def config(self) -> dict[str, Any]:
        return {
            "detector": self.name,
            "threshold": self._threshold,
            "hf_id": self.spec.hf_id,
            "revision": self._revision,
            "licence": self.spec.licence,
            "parameters": self.spec.parameters,
            "device": self._device,
            "max_length": self.spec.max_length,
        }

    def scope(self) -> frozenset[Category]:
        return self.spec.scope

    async def warmup(self) -> None:
        """Load and exercise the model before any timing happens.

        Without this the first sample absorbs multi-second model loading and the
        latency distribution is nonsense.
        """
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._tokenizer = AutoTokenizer.from_pretrained(self.spec.hf_id)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.spec.hf_id)
        self._model.eval()
        self._model.to(self._device)

        # Resolve the positive class from the model's own config rather than
        # assuming index 1. Label vocabularies differ between candidates, and
        # guessing would silently invert one model's predictions.
        id2label = {int(k): str(v) for k, v in self._model.config.id2label.items()}
        wanted = self.spec.attack_label.upper()
        for index, label in id2label.items():
            if label.upper() == wanted:
                self._attack_index = index
                break
        else:
            attackish = [
                index
                for index, label in id2label.items()
                if any(
                    token in label.upper()
                    for token in ("INJECT", "JAILBREAK", "UNSAFE", "MALICIOUS", "ATTACK")
                )
            ]
            if len(attackish) != 1:
                raise RuntimeError(
                    f"{self.spec.hf_id}: cannot identify the attack class from id2label="
                    f"{id2label}. Refusing to guess."
                )
            self._attack_index = attackish[0]

        self._revision = getattr(self._model.config, "_commit_hash", None)

        with torch.no_grad():
            encoded = self._tokenizer(
                "warmup", return_tensors="pt", truncation=True, max_length=self.spec.max_length
            )
            self._model(**encoded)

    async def aclose(self) -> None:
        self._model = None
        self._tokenizer = None

    async def predict(self, sample: Sample) -> Prediction:
        import torch

        started = time.perf_counter()
        encoded = self._tokenizer(
            sample.text,
            return_tensors="pt",
            truncation=True,
            max_length=self.spec.max_length,
        )
        preprocess_ms = (time.perf_counter() - started) * 1000.0

        started = time.perf_counter()
        try:
            with torch.no_grad():
                logits = self._model(**encoded).logits
            score = float(torch.softmax(logits, dim=-1)[0, self._attack_index])
        except Exception as exc:
            return Prediction(
                sample_id=sample.sample_id,
                score=0.0,
                detected_at_configured_threshold=False,
                reasons=(),
                errored=True,
                error_kind=type(exc).__name__,
                preprocess_ms=preprocess_ms,
                inference_ms=(time.perf_counter() - started) * 1000.0,
            )
        inference_ms = (time.perf_counter() - started) * 1000.0

        return Prediction(
            sample_id=sample.sample_id,
            score=score,
            detected_at_configured_threshold=score >= self._threshold,
            reasons=(),
            errored=False,
            error_kind=None,
            preprocess_ms=preprocess_ms,
            inference_ms=inference_ms,
        )


def build_candidate(
    name: str, *, threshold: float = 0.5, device: str = "cpu"
) -> TransformerCandidate:
    spec = CANDIDATES.get(name)
    if spec is None:
        raise ValueError(f"unknown candidate {name!r}; known: {', '.join(sorted(CANDIDATES))}")
    return TransformerCandidate(spec, threshold=threshold, device=device)


def candidate_names() -> list[str]:
    return sorted(CANDIDATES)
