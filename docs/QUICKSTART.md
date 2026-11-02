# Quick start (no command line needed)

You need two things: **`surreal.exe`** and a **patch file** (a `.morph` file).
A patch file is what someone publishes when they work out how to change a program
— it contains the edits, not a copy of the program.

## 1. Download `surreal.exe`

From [Releases](../../releases/latest). There is nothing to install. Windows may warn
that the file is unsigned (it is, deliberately — see [LEGAL.md](LEGAL.md)); choose
"More info → Run anyway" if you trust where you got it.

Optional but recommended, in PowerShell in the download folder:

```powershell
certutil -hashfile surreal.exe SHA256
```

The result must match the hash in the release notes.

## 2. Put the patch file next to the program

Copy the `.morph` file into the same folder as the `.exe` it patches. Any of these
also works:

| Where | Example |
|---|---|
| next to the program | `C:\Program Files\SomeApp\my-patch.morph` |
| a `patches` folder next to it | `C:\Program Files\SomeApp\patches\my-patch.morph` |
| your Downloads or Desktop | `C:\Users\you\Downloads\my-patch.morph` |
| a folder you name | set `SURREAL_PATCHES=C:\patches` once, in System Properties → Environment Variables |

## 3. Drag the program onto `surreal.exe`

Find the `.exe` you want to patch (in File Explorer, enable *View → File name
extensions* so you can see it), and drag it onto `surreal.exe`. A console window
opens and shows something like:

```
surreal easy mode - paste or drag a file

  program:               SomeApp.exe
  bytes:                 4,120,576

    [1] Quiet the update banner  (com.example.quiet-banner)   can be applied
    [2] Bigger font              (com.example.big-font)       skipped - made for a different build of this program

  Before the first change, one confirmation. Please read the five points ...
  Do all five apply to you? (y/N)
  Apply which? 'a' = all of the above, '1 3' = those numbers, Enter = all, 'q' = quit.
  choice:
```

Answer `y`, then type `1` (or `a` for all applicable), then `y` again. That is the
whole process. "Skipped – made for a different build" means the patch was written
for another version of the program: find the matching patch or update you app —
never force it.

## 4. If something is wrong

```
surreal.exe undo SomeApp.exe          # put the original bytes back (one command)
surreal.exe history SomeApp.exe       # what was changed, when, with which patch
surreal.exe restore SomeApp.exe --from 2   # go back to an earlier state
surreal.exe doctor SomeApp.exe        # why a patch will not apply, in plain words
```

Every change is backed up first, in a `.surreal` folder next to the program, and
verified against its SHA-256 before it is used. Nothing is written unless the new
file re-reads as a valid Windows program.

## 5. A whole folder at once

Drag the **folder** instead of the file. Every `.morph` inside it is paired with
the program it matches and applied as one transaction — if any file fails, all of
them are put back. A folder with a `surreal-collection.json` (a published patch
set often has one) is applied in its declared order.

## Making your own patch

You need two builds of the same program: the original, and the one you edited (a
hex editor, a recompiled build, a translated resource, whatever you are allowed to
do).

```powershell
surreal.exe diff original.exe edited.exe -o my-patch.morph --id com.you.my-patch
surreal.exe check my-patch.morph --target original.exe    # dry run, writes nothing
```

Add `--requires-machine --requires-section .rdata` and the patch will refuse to
apply to a build it does not recognise instead of writing the wrong bytes
([CONDITIONS.md](CONDITIONS.md)). Share the `.morph`, never a patched copy of
someone else's program.

## What this tool will not do

No DRM, activation, anti-cheat or anti-tamper circumvention, and no redistribution
of modified software — the full policy is shown by `surreal.exe init`. It patches
binaries you own or are licensed to modify: for interoperability, repair,
accessibility, translation, modding of abandoned software, and security research.
