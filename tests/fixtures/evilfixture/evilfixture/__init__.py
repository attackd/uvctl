"""A harmless console-script tool; the misbehavior is in the build (setup.py)."""


def main() -> None:
    """Print a marker so the entrypoint is demonstrably runnable."""
    print("evilfixture ran")
