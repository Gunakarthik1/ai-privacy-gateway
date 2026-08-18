"""
Prompt injection and jailbreak detection using keyword heuristics and
pattern matching. No external ML model required.
"""

import re
from typing import List, Tuple
from .models import InjectionResult, RiskLevel


# ---------------------------------------------------------------------------
# Pattern definitions
# Each entry: (pattern_name, compiled_regex, weight)
# Weights sum to produce a raw score that is normalised to [0, 1].
# ---------------------------------------------------------------------------

_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
    # ---- Jailbreak / restriction bypass ----
    (
        "ignore_previous_instructions",
        re.compile(r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?|context)", re.IGNORECASE),
        0.40,
    ),
    (
        "pretend_you_are",
        re.compile(r"pretend\s+(you\s+are|to\s+be)", re.IGNORECASE),
        0.30,
    ),
    (
        "dan_mode",
        re.compile(r"\bDAN\s+mode\b|\bdo\s+anything\s+now\b", re.IGNORECASE),
        0.45,
    ),
    (
        "jailbreak",
        re.compile(r"\bjailbreak\b", re.IGNORECASE),
        0.40,
    ),
    (
        "bypass_restrictions",
        re.compile(r"\bbypass\b.{0,30}\b(filter|restrict|guideline|rule|safety|policy)", re.IGNORECASE),
        0.35,
    ),
    (
        "act_as_no_restrictions",
        re.compile(r"act\s+as\s+(if\s+)?you\s+(have\s+)?no\s+restrict", re.IGNORECASE),
        0.40,
    ),
    # ---- Role override ----
    (
        "you_are_now",
        re.compile(r"you\s+are\s+now\s+(?!a\s+(?:helpful|kind|professional))", re.IGNORECASE),
        0.25,
    ),
    (
        "new_system_prompt",
        re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
        0.50,
    ),
    (
        "forget_everything",
        re.compile(r"forget\s+(everything|all|previous|prior)", re.IGNORECASE),
        0.35,
    ),
    (
        "disregard_instructions",
        re.compile(r"disregard\s+(all\s+)?(previous\s+)?(instructions?|rules?|guidelines?)", re.IGNORECASE),
        0.40,
    ),
    # ---- Data exfiltration ----
    (
        "repeat_everything_above",
        re.compile(r"repeat\s+(everything|all|the\s+text)\s+(above|before|prior)", re.IGNORECASE),
        0.45,
    ),
    (
        "print_system_prompt",
        re.compile(r"(print|show|reveal|display|output)\s+(your\s+)?(system\s+prompt|hidden\s+prompt|instructions?)", re.IGNORECASE),
        0.50,
    ),
    (
        "show_hidden",
        re.compile(r"show\s+(hidden|secret|internal|confidential)", re.IGNORECASE),
        0.35,
    ),
    (
        "what_are_your_instructions",
        re.compile(r"what\s+(are\s+)?your\s+(instructions?|system\s+prompt|hidden\s+rules?)", re.IGNORECASE),
        0.30,
    ),
    # ---- Social engineering / evasion framing ----
    (
        "for_educational_purposes",
        re.compile(r"for\s+educational\s+purposes", re.IGNORECASE),
        0.15,
    ),
    (
        "hypothetically_speaking",
        re.compile(r"hypothetically\s+speaking", re.IGNORECASE),
        0.15,
    ),
    (
        "in_a_fictional_world",
        re.compile(r"in\s+a\s+fictional\s+(world|universe|scenario|story)", re.IGNORECASE),
        0.10,
    ),
    (
        "as_a_character",
        re.compile(r"as\s+a\s+character\s+(who\s+)?(has\s+no|without|ignores?)", re.IGNORECASE),
        0.25,
    ),
    # ---- Prompt delimiter injection ----
    (
        "delimiter_injection",
        re.compile(r"(</?(system|user|assistant|instructions?)>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)", re.IGNORECASE),
        0.45,
    ),
    # ---- Token smuggling / encoding tricks ----
    (
        "base64_instruction",
        re.compile(r"base64\s+(decode|encode).{0,40}(run|execute|follow|instruction)", re.IGNORECASE),
        0.40,
    ),
    (
        "unicode_override",
        re.compile(r"[\u202e\u200f\u200e\u2066-\u2069]"),  # RTL / bidi override
        0.50,
    ),
]

# Threshold above which a single pattern's weight alone triggers MEDIUM risk.
# Patterns with weight >= this value are considered individually significant.
_SINGLE_PATTERN_MEDIUM_THRESHOLD = 0.25

# Ceiling raw score used to normalise combined multi-pattern scores into [0,1].
# Chosen so that ~3 medium-weight patterns together reach HIGH/CRITICAL.
_NORMALISATION_CEILING = 1.20


def _risk_level(confidence: float) -> RiskLevel:
    if confidence >= 0.85:
        return RiskLevel.CRITICAL
    if confidence >= 0.55:
        return RiskLevel.HIGH
    if confidence >= 0.30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


class InjectionDetector:
    """
    Detects prompt injection and jailbreak attempts using heuristic pattern matching.
    """

    def classify(self, prompt: str) -> InjectionResult:
        """
        Classify a prompt for injection risk.

        Scoring strategy:
          1. Any pattern with weight >= 0.25 is individually significant — its
             presence alone guarantees at least MEDIUM risk (confidence >= 0.30).
          2. Multiple matches accumulate additively.
          3. The raw accumulated score is normalised against a ceiling chosen so
             that 2–3 high-weight patterns reach CRITICAL territory.

        Returns an InjectionResult with:
            - is_injection: True if risk level >= MEDIUM
            - confidence: score in [0, 1]
            - matched_patterns: names of triggered patterns
            - risk_level: low / medium / high / critical
        """
        matched: List[str] = []
        raw_score = 0.0
        max_single_weight = 0.0

        for name, pattern, weight in _PATTERNS:
            if pattern.search(prompt):
                matched.append(name)
                raw_score += weight
                if weight > max_single_weight:
                    max_single_weight = weight

        if not matched:
            return InjectionResult(
                is_injection=False,
                confidence=0.0,
                matched_patterns=[],
                risk_level=RiskLevel.LOW,
            )

        # Ensure individually significant patterns always hit >= MEDIUM.
        # Map max_single_weight [0.25, 0.50] → confidence [0.30, 0.60].
        # For weights below 0.25 (social engineering), the combined score
        # may still accumulate to MEDIUM if several fire together.
        if max_single_weight >= _SINGLE_PATTERN_MEDIUM_THRESHOLD:
            # Linear mapping: weight 0.25 → 0.30, weight 0.50 → 0.60
            single_confidence = 0.30 + (max_single_weight - 0.25) / (0.50 - 0.25) * 0.30
        else:
            single_confidence = 0.0

        # Combined score — normalised against ceiling
        combined_confidence = min(1.0, raw_score / _NORMALISATION_CEILING)

        # Take the higher of the two so that individual strong patterns
        # are never suppressed by normalisation.
        confidence = min(1.0, max(single_confidence, combined_confidence))

        risk = _risk_level(confidence)
        is_injection = risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

        return InjectionResult(
            is_injection=is_injection,
            confidence=round(confidence, 4),
            matched_patterns=matched,
            risk_level=risk,
        )
