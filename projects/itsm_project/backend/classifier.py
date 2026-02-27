from typing import List, Tuple

KEYWORDS: List[Tuple[str, str]] = [
    ("reset", "Access"),
    ("login", "Access"),
    ("password", "Access"),
    ("no prende", "Hardware"),
    ("pantalla", "Hardware"),
    ("laptop", "Hardware"),
    ("mouse", "Hardware"),
    ("wifi", "Network"),
    ("internet", "Network"),
    ("vpn", "Network"),
    ("word", "Software"),
    ("excel", "Software"),
    ("office", "Software"),
    ("teams", "Software"),
    ("software", "Software"),
    ("permisos", "Permissions"),
    ("access denied", "Permissions"),
    ("carpeta", "Permissions"),
]


def classify_description(description: str) -> str:
    """Return a suggested category based on simple keyword matching."""
    lowered = description.lower()
    for keyword, category in KEYWORDS:
        if keyword in lowered:
            return category
    return "Uncategorized"
