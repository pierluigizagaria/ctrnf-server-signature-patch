# CTR:NF Server Signature Patch

For **Crash Team Racing Nitro-Fueled, CUSA13795 version 01.21**. Tested in-game on shadPS4.

## Installation

1. Extract the ZIP into the configured shadPS4 patches directory, normally `user/patches`. Keep the `ctrnf-server-signature-patch` folder intact, with `CrashTeamRacingNitroFueled.xml` and `files.json` inside it.
2. Open CTR:NF's **Cheats / Patches** window in the official Qt launcher and select the **Patches** tab. Select `CrashTeamRacingNitroFueled.xml | ctrnf-server-signature-patch`.
3. Check **CTR:NF Server Signature Patch** and click **Save**. Start or restart the game with automatic game-patch loading enabled. When using the command line, omit `--ignore-game-patch`.

To disable the patch, clear its checkbox, save and restart the game. Changes take effect when the game starts.

Python is needed only to rebuild the package, not to install it. The patch is applied in memory and leaves the game files unchanged.

## What it changes

The patch replaces the conditional jump that rejects a server response when signature verification fails. The verifier still runs, but its failure result no longer triggers that rejection branch.

Response parsing, account authentication, HTTPS validation and lobby message authentication are unchanged. The patch does not configure server addresses or provide a multiplayer server.

## Supported executable

| Property | Value |
| --- | --- |
| Title ID | `CUSA13795` |
| Application version | `01.21` |
| Executable | `eboot.bin` |
| SHA-256 | `e3b7a068b5e7be0f976102aa223a74425e7817c67e26e21416163291750c1b83` |
| Image offset | `0x13ec0` |
| shadPS4 patch address | `0x00413ec0` |
| Original bytes | `0f84fc000000` |
| Replacement bytes | `909090909090` (six NOPs) |

`build_patch.py` checks the executable SHA-256 before regenerating the patch. Release packages use the committed XML. At runtime, shadPS4 selects the patch by title ID and application version.

## References

- [shadPS4 patch format](https://github.com/shadps4-emu/ps4_cheats#patches)
- [Qt patch manager](https://github.com/shadps4-emu/shadps4-qtlauncher/blob/main/src/qt_gui/cheats_patches.cpp)
- [Emulator patch loader](https://github.com/shadps4-emu/shadPS4/blob/main/src/common/memory_patcher.cpp)

## License

MIT. See the included `LICENSE` file.
