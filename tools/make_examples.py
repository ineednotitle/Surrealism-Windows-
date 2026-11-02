#!/usr/bin/env python3
"""Regenerate `examples/` from the synthetic fixture (reproducible bundles).

    python tools/make_examples.py

Examples target the demo app that `surreal demo` writes — a generated PE, so no
third-party binary and no licensing question is involved.
"""

import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal import repo  # noqa: E402
from surreal import surgery  # noqa: E402
from surreal.diffgen import build_bundle  # noqa: E402
from surreal.patchfile import Bundle  # noqa: E402
from surreal.pe import PE  # noqa: E402
from surreal.testkit import make_pe_pair, sample_app  # noqa: E402

EXTRA_SECTION_BYTES = (b"\r\n[SURREAL-DEMO]\r\n"
                       b"payload=grown-in-place-by-header-surgery\r\n")

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

        # a third, size-preserving bundle: blank the version string
        versioned = bytearray(base)
        needle = b"Version 1.0.0 build 2026-11-01"
        at = versioned.find(needle)
        if at >= 0:
            versioned[at:at + len(needle)] = b"\0" * len(needle)
            modified = os.path.join(tmp, "demo_app_noversion.exe")
            with open(modified, "wb") as fh:
                fh.write(bytes(versioned))
            vb, _ = build_bundle(
                old, modified,
                bundle_id="org.surreal.demo.blank-version",
                name="Demo: blank the version string",
                author="surreal demo",
                description="Hides the build string in .rdata. Size-preserving, so "
                            "it can be combined with other patches in a collection.",
                created_utc="2026-11-01T00:00:00Z",
            )
            out3 = os.path.join(EXAMPLES, "demo-blank-version.morph")
            vb.save(out3)
            print("wrote %s (%d hunk(s))" % (out3, len(vb.hunks)))

        # a header-surgery bundle: grow the last section in place
        grown_section = os.path.join(tmp, "demo_app_extended.exe")
        shutil.copyfile(old, grown_section)
        pe = PE.open(grown_section)
        try:
            plan = surgery.plan_extend_section(pe, pe.sections[-1].name,
                                               EXTRA_SECTION_BYTES)
        finally:
            pe.close()
        with open(grown_section, "r+b") as fh:
            for offset, data in plan.writes:
                fh.seek(offset)
                fh.write(data)
            fh.seek(0, os.SEEK_END)
            fh.write(plan.payload)
        with PE.open(grown_section) as after:
            csum, skip = after.compute_checksum(), after._checksum_offset
        with open(grown_section, "r+b") as fh:
            fh.seek(skip)
            fh.write(struct.pack("<I", csum))
        sb, _ = build_bundle(
            old, grown_section,
            bundle_id="org.surreal.demo.extend-section",
            name="Demo: grow the last section",
            author="surreal demo",
            description=("Appends %d bytes to the last section and rewrites "
                         "VirtualSize, SizeOfRawData and SizeOfImage. This is the "
                         "header-surgery path: still declarative, still verified by "
                         "a replay during generation." % len(EXTRA_SECTION_BYTES)),
            notes=("Practice bundle for the generated demo_app.exe. Requires the "
                   "exact old build; refuses overlays and non-last sections."),
            created_utc="2026-11-01T00:00:00Z",
        )
        out4 = os.path.join(EXAMPLES, "demo-extend-section.morph")
        sb.save(out4)
        print("wrote %s (%d hunk, file %+d bytes, %s VirtualSize 0x%X)"
              % (out4, len(sb.hunks),
                 os.path.getsize(grown_section) - os.path.getsize(old),
                 sb.hunks[0].section, sb.hunks[0].virtual_size_after or 0))

        # a conditioned bundle: the patch declares the build it expects and makes
        # one hunk conditional, so it can be applied to a range of demo builds
        conditioned_path = os.path.join(EXAMPLES, "demo-shorten-nag.morph")
        conditioned = Bundle.load(conditioned_path)
        conditioned.id = "org.surreal.demo.conditional-nag"
        conditioned.name = "Demo: shorten the nag only where it still exists"
        conditioned.description = (
            "Same edit as demo-shorten-nag, but it refuses anything that is not a "
            "64-bit image with a .rdata section, and it skips the string hunk when "
            "the trial text is not in the build. This is what a .morph can do "
            "without any scripting runtime: declarative conditions, no code.")
        conditioned.requires = [
            {"machine": "x64", "comment": "authored against a 64-bit build"},
            {"section": ".rdata"},
            {"string": "Version 1.0.0", "comment": "the demo banner must be there"},
        ]
        # the string-blanking hunk only applies while the nag text is still there
        for hunk in conditioned.hunks:
            if hunk.op == "patch" and hunk.length > 8:
                hunk.when = {"string": "Trial expired."}
        out5 = os.path.join(EXAMPLES, "demo-conditional.morph")
        conditioned.save(out5)
        print("wrote %s (%d preconditions, %d conditional hunk(s))"
              % (out5, len(conditioned.requires),
                 sum(1 for h in conditioned.hunks if h.when)))

        # a collection applying two size-preserving bundles in one transaction
        manifest = {
            "format": "surreal.collection",
            "format_version": 1,
            "name": "Surrealism Window demo set",
            "description": ("Two size-preserving demo patches for the generated "
                            "demo_app.exe, applied as one transaction."),
            "author": "surreal demo",
            "patches": [
                {"bundle": "demo-shorten-nag.morph", "order": 10,
                 "description": "invert a branch and blank the nag string"},
                {"bundle": "demo-blank-version.morph", "order": 20,
                 "description": "blank the version string"},
            ],
        }
        import json as _json

        path = os.path.join(EXAMPLES, "surreal-collection.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            _json.dump(manifest, fh, indent=2)
            fh.write("\n")
        print("wrote %s (%d patches)" % (path, len(manifest["patches"])))

        # a local patch repo index over the examples themselves
        index = repo.build_index(EXAMPLES, name="Surrealism Window examples",
                                 description=("Reproducibly generated demo bundles. "
                                              "Index only — no trust implied."),
                                 base_dir=EXAMPLES,
                                 created_utc="2026-11-01T00:00:00Z")
        repo_path = os.path.join(EXAMPLES, "surreal-repo.json")
        repo.write_index(index, repo_path)
        print("wrote %s (%d bundles)" % (repo_path, len(index["bundles"])))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
