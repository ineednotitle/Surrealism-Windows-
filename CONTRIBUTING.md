# Contributing

Thanks for helping. Three rules matter more than style here.

## 1. Patches must be legal to publish

Bundles in `examples/` and PRs that add `.morph` files must target software the
contributor is allowed to modify, and must **not** defeat licence activation,
DRM, anti-cheat or anti-tamper. PRs containing such bundles are closed without
merge — see [`docs/LEGAL.md`](docs/LEGAL.md). Never include binaries, dumps or
patched executables in a PR. A bundle is JSON and small; ship that, nothing else.

## 2. Every code change keeps these invariants

* nothing is written to a target before *every* hunk resolves and verifies;
* no `read()` of a whole executable (use `mmap`, or `CHUNK`-sized reads);
* no new third-party dependency — the tool is stdlib-only, deliberately;
* no network, no subprocess, no `eval` (CI greps for these);
* every new abort path gets a test in `tests/test_patcher.py`.

## 3. Tests and docs move together

```bash
python run_tests.py         # must be green on Windows, Linux and macOS
python -m surreal selftest  # end-to-end on a generated PE
python tools/bench.py       # performance should stay in the documented budget
```

If you change the `.morph` format, update `docs/PATCH_FORMAT.md` **and** bump
`FORMAT_VERSION` in `surreal/__init__.py` if the change is not purely additive.

## Adding a new test fixture

Use `surreal/testkit.py::build_pe`: it emits real PE images byte by byte, so
tests need no sample executables and no Windows. `surreal demo` and
`surreal selftest` are built on the same helper.

## Commit style

`area: what changed` — e.g. `patcher: refuse hunks that resolve outside .text`.
Keep the *why* in the body when a safety check is involved.

## Reporting bugs

Include: `surreal --version`, OS, the command line (redact paths), the failing
output, and — for bundle problems — `surreal info <bundle> --json`. Do not attach
third-party executables; attach a minimal generated fixture if you can.
