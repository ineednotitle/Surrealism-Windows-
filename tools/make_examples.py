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
from surreal.testkit import make_pe_pair, sample_app  # noqa: E402

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

        # a second example: an overlay append (the only size change v1 allows)
        grown = os.path.join(tmp, "demo_app_overlay.exe")
        with open(old, "rb") as fh:
            base = fh.read()
        payload = (b"\r\n[SURREAL-DEMO]\r\noverlay=appended-by-surreal\r\n"
                   b"purpose=demonstrate-size-changing-patch\r\n")
        with open(grown, "wb") as fh:
            fh.write(base + payload)
        overlay, ostats = build_bundle(
            old, grown,
            bundle_id="org.surreal.demo.append-overlay",
            name="Demo: append an overlay config blob",
            author="surreal demo",
            description=("Appends %d bytes after the last section. Overlay growth "
                         "is the only size change that needs no header, section "
                         "table or RVA fixups." % len(payload)),
            notes=("Practice bundle for the generated demo_app.exe. The append is "
                   "verified by the target hash; truncate is the inverse op."),
            created_utc="2026-11-01T00:00:00Z",
        )
        out2 = os.path.join(EXAMPLES, "demo-append-overlay.morph")
        overlay.save(out2)
        print("wrote %s (%d hunk, %+d bytes)" % (out2, len(overlay.hunks),
                                                 ostats["size_delta"]))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
