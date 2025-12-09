"""Feature extraction for Portable Executable (PE) files.

This module extracts the numeric fields expected by the ransomware
classifier from an uploaded Windows PE (.exe) file. All fields are
returned as numbers in the exact order used by the training pipeline.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import pefile

# Silence Pylance unknown-member noise from third-party stubs
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

# Ordered list of features the model expects
FEATURE_COLUMNS: List[str] = [
    "Machine",
    "DebugSize",
    "DebugRVA",
    "MajorImageVersion",
    "MajorOSVersion",
    "ExportRVA",
    "ExportSize",
    "IatVRA",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses",
]

# Regex for loose Bitcoin address search (simplified to avoid heavy validation)
_BTC_REGEX = re.compile(rb"[13][a-km-zA-HJ-NP-Z1-9]{25,34}")


def _count_bitcoin_addresses(raw_bytes: bytes) -> int:
    """Return count of Bitcoin-looking substrings in the binary payload."""
    return len(_BTC_REGEX.findall(raw_bytes))


def _get_dir_entry(pe: pefile.PE, entry_name: str) -> Optional[Any]:
    try:
        idx: int = pefile.DIRECTORY_ENTRY[entry_name]
        opt_header = getattr(pe, "OPTIONAL_HEADER", None)
        data_dir = getattr(opt_header, "DATA_DIRECTORY", None)
        if data_dir is not None:
            return data_dir[idx]
        return None
    except Exception:
        return None


def extract_features(file_path: str | Path) -> Dict[str, float]:
    """Extract numeric features from a PE file.

    Raises
    ------
    ValueError
        If the file is missing or not a valid PE binary.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise ValueError(f"File not found: {file_path}")

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
        pe.parse_data_directories()
    except pefile.PEFormatError as exc:  # not a PE file
        raise ValueError(f"Invalid PE file: {exc}") from exc

    # Read bytes once for BTC scan (avoid multiple disk reads)
    try:
        raw_bytes = file_path.read_bytes()
    except Exception:
        raw_bytes = b""

    debug_dir = _get_dir_entry(pe, "IMAGE_DIRECTORY_ENTRY_DEBUG")
    export_dir = _get_dir_entry(pe, "IMAGE_DIRECTORY_ENTRY_EXPORT")
    iat_dir = _get_dir_entry(pe, "IMAGE_DIRECTORY_ENTRY_IAT")
    resource_dir = _get_dir_entry(pe, "IMAGE_DIRECTORY_ENTRY_RESOURCE")

    features: Dict[str, float] = {
        "Machine": int(getattr(pe.FILE_HEADER, "Machine", 0)),
        "DebugSize": int(getattr(debug_dir, "Size", 0) or 0),
        "DebugRVA": int(getattr(debug_dir, "VirtualAddress", 0) or 0),
        "MajorImageVersion": int(getattr(pe.OPTIONAL_HEADER, "MajorImageVersion", 0)),
        "MajorOSVersion": int(getattr(pe.OPTIONAL_HEADER, "MajorOperatingSystemVersion", 0)),
        "ExportRVA": int(getattr(export_dir, "VirtualAddress", 0) or 0),
        "ExportSize": int(getattr(export_dir, "Size", 0) or 0),
        "IatVRA": int(getattr(iat_dir, "VirtualAddress", 0) or 0),
        "MajorLinkerVersion": int(getattr(pe.OPTIONAL_HEADER, "MajorLinkerVersion", 0)),
        "MinorLinkerVersion": int(getattr(pe.OPTIONAL_HEADER, "MinorLinkerVersion", 0)),
        "NumberOfSections": int(getattr(pe.FILE_HEADER, "NumberOfSections", 0)),
        "SizeOfStackReserve": int(getattr(pe.OPTIONAL_HEADER, "SizeOfStackReserve", 0)),
        "DllCharacteristics": int(getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)),
        "ResourceSize": int(getattr(resource_dir, "Size", 0) or 0),
        "BitcoinAddresses": int(_count_bitcoin_addresses(raw_bytes)),
    }

    # Ensure ordering and numeric types
    ordered = {name: float(features.get(name, 0)) for name in FEATURE_COLUMNS}
    return ordered


def compute_md5(file_path: str | Path) -> str:
    """Compute MD5 for reference/logging; not used by the model."""
    file_path = Path(file_path)
    hash_md5 = hashlib.md5()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


__all__ = ["extract_features", "FEATURE_COLUMNS", "compute_md5"]
