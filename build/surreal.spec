# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec → a single surreal.exe with no external dependencies.

    python -m PyInstaller --clean --noconfirm build/surreal.spec

Design notes (4 GB / low-end target): one file, no UPX, no console hiding, no
version resource magic. Excluding optional stdlib packages keeps the binary
small and start-up fast; surreal imports none of them.
"""

import os
import sys

block_cipher = None
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(ROOT, "surreal", "cli.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        "surreal", "surreal.cli", "surreal.pe", "surreal.scanner",
        "surreal.patchfile", "surreal.diffgen", "surreal.patcher",
        "surreal.journal", "surreal.policy", "surreal.testkit", "surreal.util",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "unittest", "pydoc", "doctest", "test", "lib2to3",
        "email", "html", "http", "xmlrpc", "urllib.request", "ssl", "socket",
        "asyncio", "multiprocessing", "concurrent", "pydoc_data",
        "ctypes.test", "distutils", "setuptools", "pip", "venv",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="surreal",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,              # never pack: AV heuristics hate packed patchers
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,           # CLI tool
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
