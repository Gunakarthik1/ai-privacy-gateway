"""
PII detection and masking pipeline using regex patterns and heuristics.
No external ML dependencies required.
"""

import re
import hashlib
from typing import List, Tuple
from .models import PIIEntity, PIIMaskResult, PIIScanReport


# ---------------------------------------------------------------------------
# Luhn algorithm for credit card validation
# ---------------------------------------------------------------------------

def _luhn_valid(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE": re.compile(
        r"(?<!\d)(?:\+1[\s\-.]?)?"
        r"(?:\(?\d{3}\)?[\s\-.]?)"
        r"\d{3}[\s\-.]?\d{4}(?!\d)"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "API_KEY": re.compile(
        r"(?:"
        r"sk-[A-Za-z0-9]{20,}"
        r"|Bearer\s+[A-Za-z0-9\-._~+/]{20,}"
        r"|AIza[A-Za-z0-9\-_]{35}"
        r"|ghp_[A-Za-z0-9]{36}"
        r"|xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+"
        r"|ya29\.[A-Za-z0-9\-_]+"
        r")"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:\d[ \-]?){13,19}\b"
    ),
    "DOB": re.compile(
        r"(?:born\s+on|date\s+of\s+birth|DOB|dob)\s*[:\-]?\s*"
        r"(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"
        r"|\b(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2},?\s+\d{4}\b)",
        re.IGNORECASE,
    ),
    "NAME": re.compile(
        r"(?:my name is|I am|I'm|signed by|this is)\s+"
        r"([A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20})",
        re.IGNORECASE,
    ),
}

_REPLACEMENTS = {
    "SSN": "[SSN_REDACTED]",
    "EMAIL": "[EMAIL_REDACTED]",
    "PHONE": "[PHONE_REDACTED]",
    "IP_ADDRESS": "[IP_REDACTED]",
    "API_KEY": "[API_KEY_REDACTED]",
    "CREDIT_CARD": "[CC_REDACTED]",
    "DOB": "[DOB_REDACTED]",
    "NAME": "[NAME_REDACTED]",
}


class PIIInspector:
    """Detects and masks PII in text using regex patterns and heuristics."""

    def _find_entities(self, text: str) -> List[PIIEntity]:
        """Find all PII entities in text, returning a sorted, deduplicated list."""
        raw_matches: List[Tuple[int, int, str, str]] = []  # (start, end, type, value)

        # Standard pattern matches
        for entity_type, pattern in _PATTERNS.items():
            if entity_type in ("DOB", "NAME"):
                # These patterns have capturing groups for the sensitive part
                for m in pattern.finditer(text):
                    # group(0) is the whole match, group(1) is the capture
                    if m.lastindex and m.lastindex >= 1:
                        raw_matches.append((m.start(), m.end(), entity_type, m.group(0)))
                    else:
                        raw_matches.append((m.start(), m.end(), entity_type, m.group(0)))
            elif entity_type == "CREDIT_CARD":
                for m in pattern.finditer(text):
                    digits_only = re.sub(r"[ \-]", "", m.group(0))
                    if len(digits_only) in (13, 14, 15, 16, 17, 18, 19) and _luhn_valid(digits_only):
                        raw_matches.append((m.start(), m.end(), entity_type, m.group(0)))
            else:
                for m in pattern.finditer(text):
                    raw_matches.append((m.start(), m.end(), entity_type, m.group(0)))

        # Sort by start position
        raw_matches.sort(key=lambda x: x[0])

        # Remove overlapping matches — keep the first (longest / earliest)
        entities: List[PIIEntity] = []
        covered_until = -1
        for start, end, entity_type, value in raw_matches:
            if start < covered_until:
                continue
            entities.append(
                PIIEntity(
                    entity_type=entity_type,
                    original_value=value,
                    replacement=_REPLACEMENTS[entity_type],
                    start=start,
                    end=end,
                )
            )
            covered_until = end

        return entities

    def mask(self, text: str) -> Tuple[str, List[PIIEntity]]:
        """
        Mask PII in text.

        Returns:
            (masked_text, list_of_pii_entities)
        """
        entities = self._find_entities(text)
        if not entities:
            return text, []

        # Build masked string by replacing from right to left
        # (preserves positions of earlier entities)
        result = text
        for entity in reversed(entities):
            result = result[: entity.start] + entity.replacement + result[entity.end :]

        return result, entities

    def unmask(self, masked_text: str, entities: List[PIIEntity]) -> str:
        """
        Restore original values from a previously masked text.
        Works by replacing placeholder tokens back in order.
        """
        result = masked_text
        # Process entities in reverse order of original position so string
        # offsets stay valid if placeholders differ in length.
        # However, after masking the positions shift, so we replace by value.
        # We track which occurrences have been replaced to handle duplicates.
        replacement_counts: dict = {}
        for entity in entities:
            key = entity.replacement
            replacement_counts[key] = replacement_counts.get(key, 0) + 1

        # For each placeholder type, replace occurrences one by one
        # mapping back to original values in order
        placeholder_queue: dict = {}
        for entity in entities:
            placeholder_queue.setdefault(entity.replacement, []).append(entity.original_value)

        for placeholder, originals in placeholder_queue.items():
            for original in originals:
                result = result.replace(placeholder, original, 1)

        return result

    def scan_only(self, text: str) -> PIIScanReport:
        """
        Return a detection report without modifying the text.
        """
        entities = self._find_entities(text)
        entity_types = list({e.entity_type for e in entities})
        risk_score = min(1.0, len(entities) * 0.15 + (0.3 if entities else 0.0))

        return PIIScanReport(
            original_text=text,
            entities=entities,
            entity_count=len(entities),
            entity_types=entity_types,
            risk_score=risk_score,
        )

    def mask_result(self, text: str) -> PIIMaskResult:
        """Convenience method returning a structured PIIMaskResult."""
        masked_text, entities = self.mask(text)
        return PIIMaskResult(
            masked_text=masked_text,
            entities=entities,
            entity_count=len(entities),
        )
