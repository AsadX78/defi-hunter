#!/usr/bin/env python3
"""Validate all attack templates: structure + Solidity compilation.

Extracts each template's Solidity PoC and compiles it with solc.
Exit code 1 on any failure.

Usage:
    python3 scripts/check_templates.py            # use system solc
    python3 scripts/check_templates.py --solc /path/to/solc
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from defihunter.templates import TEMPLATES  # noqa: E402

REQUIRED_FIELDS = ['type', 'severity', 'title', 'description',
                   'contracts', 'steps', 'mitigation', 'code']


def check_structure() -> list:
    errors = []
    for name, tpl in TEMPLATES.items():
        for field in REQUIRED_FIELDS:
            if field not in tpl:
                errors.append(f'{name}: missing field {field}')
        if 'contract ' not in tpl.get('code', ''):
            errors.append(f'{name}: code has no contract declaration')
        if 'pragma solidity' not in tpl.get('code', ''):
            errors.append(f'{name}: code missing pragma')
    return errors


def check_compile(solc: str) -> list:
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name, tpl in TEMPLATES.items():
            src = tmp / f'{name}.sol'
            src.write_text(tpl['code'])
            result = subprocess.run(
                [solc, '--bin', str(src)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                errors.append(f'{name}: solc failed:\n{result.stdout}{result.stderr}')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solc', default=shutil.which('solc') or 'solc')
    args = parser.parse_args()

    print(f'[*] Validating {len(TEMPLATES)} templates (structure)...')
    structure_errors = check_structure()
    if structure_errors:
        for e in structure_errors:
            print(f'  [FAIL] {e}')
        print(f'[-] {len(structure_errors)} structure error(s)')
        return 1
    print(f'[+] Structure OK ({len(TEMPLATES)} templates)')

    print(f'[*] Compiling with {args.solc}...')
    compile_errors = check_compile(args.solc)
    if compile_errors:
        for e in compile_errors:
            print(f'  [FAIL] {e}')
        print(f'[-] {len(compile_errors)} compile error(s)')
        return 1
    print(f'[+] All {len(TEMPLATES)} templates compile OK')

    types = sorted({t['type'] for t in TEMPLATES.values()})
    print(f'[+] Coverage: {", ".join(types)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
