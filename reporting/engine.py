from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Iterable


def build_summary(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(records)
    return {
        "count": len(rows),
        "devices": sum(1 for row in rows if row.get("kind") == "device"),
        "alerts": sum(1 for row in rows if row.get("kind") == "alert"),
        "transfers": sum(1 for row in rows if row.get("kind") == "transfer"),
    }


def export_csv(records: Iterable[dict[str, Any]], destination: str | os.PathLike[str]) -> str:
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in records for key in row.keys()})
    rows = list(records)
    with destination_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return str(destination_path)
