#!/usr/bin/env python3
"""Regenerate `examples/` from the synthetic fixture (reproducible bundles).

    python tools/make_examples.py

Examples target the demo app that `surreal demo` writes — a generated PE, so no
third-party binary and no licensing question is involved.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal.diffgen import build_bundle  # noqa: E402
from surreal.testkit import make_pe_pair  # noqa: E402

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "examples")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="surreal-examples-")
    try:
        old, new = make_pe_pair(tmp)
        bundle, stats = build_bundle(
            old, new,
            bundle_id="org.surreal.demo.shorten-nag",
            name="Demo: blank the trial nag + flip one branch",
            author="surreal demo",
            description=("Generated from surreal.testkit fixtures. Two edits: a "
                         "conditional jump is inverted and the nag string is "
                         "blanked in place. Same-length, size-preserving."),
            notes=("This is a practice bundle for the generated demo_app.exe. "
                   "It is not a patch for any real product."),
            created_utc="2026-11-01T00:00:00Z",  # fixed → reproducible output
        )
        out = os.path.join(EXAMPLES, "demo-shorten-nag.morph")
        bundle.save(out)
        print("wrote %s (%d hunks, %d anchored)" % (out, len(bundle.hunks),
                                                    stats["anchored"]))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
