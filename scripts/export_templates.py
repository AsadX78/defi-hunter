#!/usr/bin/env python3
"""Export the template Solidity PoCs into the Foundry lab.

Writes each template's `code` field to lab/src/attacks/{name}.sol so that
the forge test suite in lab/ can import and run the exact template exploits.

Usage:
    python3 scripts/export_templates.py [--out lab/src/attacks]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from defihunter.templates import TEMPLATES  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default=str(Path(__file__).resolve().parent.parent / 'lab' / 'src' / 'attacks'))
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, tpl in TEMPLATES.items():
        (out / f'{name}.sol').write_text(tpl['code'])
        count += 1
        print(f'  [+] {name}.sol')

    print(f'\n[+] Exported {count} template attack contracts to {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
