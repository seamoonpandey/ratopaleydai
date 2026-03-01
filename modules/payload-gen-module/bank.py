"""
bank — loads and queries the 24k+ xss payload database
reads from csv dataset and indexes payloads by context and technique
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
PAYLOADS_FILE = DATA_DIR / "processed" / "payloads_labeled.csv"
FALLBACK_FILE = DATA_DIR / "splits" / "train.csv"


@dataclass
class PayloadEntry:
    payload: str
    context: str
    technique: str
    severity: str
    length: int
    source: str = "real"


class PayloadBank:
    def __init__(self):
        self.entries: list[PayloadEntry] = []
        self.by_context: dict[str, list[PayloadEntry]] = {}
        self._load()

    def _load(self):
        """load payloads from csv into memory"""
        path = PAYLOADS_FILE if PAYLOADS_FILE.exists() else FALLBACK_FILE

        if not path.exists():
            logger.warning(f"no payload file found at {path}")
            return

        try:
            df = pd.read_csv(path, on_bad_lines="skip")
            required = {"payload", "context", "severity"}
            if not required.issubset(set(df.columns)):
                logger.error(f"missing columns in {path}, need {required}")
                return

            for _, row in df.iterrows():
                entry = PayloadEntry(
                    payload=str(row["payload"]),
                    context=str(row.get("context", "generic")),
                    technique=str(row.get("technique", "none")),
                    severity=str(row.get("severity", "medium")),
                    length=int(row.get("length", len(str(row["payload"])))),
                    source=str(row.get("source", "real")),
                )
                self.entries.append(entry)

                ctx = entry.context
                if ctx not in self.by_context:
                    self.by_context[ctx] = []
                self.by_context[ctx].append(entry)

            logger.info(
                f"loaded {len(self.entries)} payloads from {path} "
                f"across {len(self.by_context)} contexts"
            )

        except Exception as e:
            logger.error(f"failed to load payload bank: {e}")

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def contexts(self) -> list[str]:
        return list(self.by_context.keys())

    def query(
        self,
        context: str | None = None,
        severity: str | None = None,
        max_length: int | None = None,
        limit: int = 100,
    ) -> list[PayloadEntry]:
        """query payloads by context, severity, and max length"""
        results = self.entries

        if context:
            results = self.by_context.get(context, [])

        if severity:
            results = [e for e in results if e.severity == severity]

        if max_length:
            results = [e for e in results if e.length <= max_length]

        return results[:limit]

    def query_by_contexts(
        self,
        contexts: list[str],
        limit_per_context: int = 50,
    ) -> dict[str, list[PayloadEntry]]:
        """query payloads for multiple contexts at once"""
        result: dict[str, list[PayloadEntry]] = {}
        for ctx in contexts:
            result[ctx] = self.query(context=ctx, limit=limit_per_context)
        return result
