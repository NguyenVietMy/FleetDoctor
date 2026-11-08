"""Validate every allowlisted portable Ticket12 postmortem example in a checkout."""

import argparse
from pathlib import Path

from fleetdoctor.postmortem import DraftingError, validate_portable_example


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("docs/postmortems"))
    args = parser.parse_args()
    if not args.root.exists():
        print("no published postmortem examples (pending)")
        return 0
    examples = sorted(item for item in args.root.iterdir() if item.is_dir())
    if not examples:
        print("no published postmortem examples (pending)")
        return 0
    try:
        for example in examples:
            validate_portable_example(example)
    except DraftingError as exc:
        print(f"invalid published postmortem example: {exc}")
        return 1
    print(f"validated {len(examples)} published postmortem example(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
