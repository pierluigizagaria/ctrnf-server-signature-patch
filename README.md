# CTR:NF Server Signature Patch

A shadPS4 patch for **Crash Team Racing Nitro-Fueled (CTR:NF)** that allows the game to
accept server responses signed with a different key.

Supports **CUSA13795, version 01.21**. Tested in-game on shadPS4.

## Installation

Download the ZIP from [Releases](https://github.com/pierluigizagaria/ctrnf-server-signature-patch/releases).
Follow the [installation instructions](docs/INSTALLATION.md) to install it
and enable the patch in the Qt launcher. The patch is disabled by default.

The patch bypasses the game's rejection of server-response signatures. Account
authentication, HTTPS validation and lobby message authentication are unchanged.
Server setup and address configuration are separate from installing this patch.

## Build the package

Requires Python 3.11 or later. To package the committed patch without game files:

```powershell
python tools/package_patch.py
```

To verify the original executable and regenerate the patch:

```powershell
python -m pip install -r requirements.txt
python tools/build_patch.py --game-dir "C:/path/to/CUSA13795"
```

The game directory must contain `eboot.bin` and `sce_sys/param.sfo`. The builder
checks the executable hash, title, version and original instructions, then
regenerates the XML and title index and writes the ZIP and verification report
to `dist/`. It leaves the game files unchanged. Identical inputs produce an
identical ZIP. The verification report remains in `dist/`; the ZIP contains the
patch, title index, installation instructions and MIT license.

## Releases

Publishing a GitHub release, including a prerelease, automatically builds and
attaches `ctrnf-server-signature-patch-CUSA13795-01.21.zip`. Pushes to `main` and
pull requests also validate the package. The workflow requires no game files.

## Files

| Path | Contents |
| --- | --- |
| `CrashTeamRacingNitroFueled.xml` | shadPS4 patch |
| `files.json` | Supported title index |
| `docs/INSTALLATION.md` | Installation instructions and technical details |
| `tools/build_patch.py` | Build verification and packaging |
| `tools/package_patch.py` | Packaging from public source files |
| `tools/orbis_image.py` | SELF/ELF address mapping |
| `.github/workflows/release.yml` | Package validation and release upload |
| `LICENSE` | MIT license |
| `dist/static-audit.json` | Generated verification report |
| `dist/ctrnf-server-signature-patch-CUSA13795-01.21.zip` | Generated installable package |

Generated files in `dist/` are excluded from Git. No game files are included.

## License

[MIT License](LICENSE).
