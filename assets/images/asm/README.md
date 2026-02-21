## Assembly Screenshot Slots

Place the following images in this folder to populate the blog sections already wired in markdown:

- `asm_mw_apihashing_pseudocode.png`  
  Used in: loader API hash resolution section (partial-evidence context image).
- `asm_mw_decrypt_keyschedule.png`  
  Used in: `mw_decrypt` byte-transform section.
- `asm_patch_43CD83_disasm.png`  
  Used in: patching/genetics section near `0x43CD83`.
- `asm_seh_48A890.png`  
  Used in: SEH/VEH explainer section.

High-priority screenshots still requested (not wired yet):

- `log.dll` handoff around `0x10001B20..0x10001C11` (`VirtualProtect` + handoff call).
- resolver callsite with `push 47C204CAh` and call to resolver function.
- patched main-module view around `0x4863A0` (optional additional patch anchor).
