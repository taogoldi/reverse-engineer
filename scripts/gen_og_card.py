#!/usr/bin/env python3
"""
Generate the site-level OG / Twitter card for taogoldi.github.io/reverse-engineer.

Output: /assets/images/social/reverse-engineer-card.png  (1200x630, OG-standard)

Edit the CONFIG block below to iterate on layout, colors, copy, and hex-dump
content. Re-run to regenerate.
"""

from PIL import Image, ImageDraw, ImageFont, ImageFilter
import random
import os

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

OUT_PATH = os.path.join(
    os.path.dirname(__file__),
    "..", "assets", "images", "social", "reverse-engineer-card.png",
)

W, H = 1200, 630

BG       = (15,  15,  18)     # #0f0f12 -- a touch darker than site bg
PANEL    = (24,  24,  29)     # #18181d
BORDER   = (60,  60,  68)     # subtle border
TEXT_HI  = (240, 240, 240)    # title
TEXT_MED = (170, 170, 175)    # subtitle / body
TEXT_LO  = (110, 110, 118)    # background hex dump
ACCENT   = (227,  60,  73)    # #e33c49 - malware/red accent

TITLE       = "Reverse Engineer"
SUBTITLE    = "Threat Intel  ·  Malware Reversing  ·  Reproducible Analysis"
AUTHOR      = "Tao Goldi"
SITE_URL    = "taogoldi.github.io/reverse-engineer"
PROMPT_TAG  = "$ tao@goldi:~/re"

# Background hex-dump text. Uses real x64 instructions for vibe; nothing
# malicious, just byte sequences and disassembly-style pairs.
HEX_DUMP_LINES = [
    "00401000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00   MZ..............",
    "00401010  B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00   ........@.......",
    "00401020  48 89 5C 24 08  push    rbx",
    "00401025  48 89 6C 24 10  push    rbp",
    "0040102A  48 89 74 24 18  push    rsi",
    "0040102F  57              push    rdi",
    "00401030  48 83 EC 20     sub     rsp, 20h",
    "00401034  48 8B F1        mov     rsi, rcx",
    "00401037  E8 D4 02 00 00  call    sub_401310",
    "0040103C  85 C0           test    eax, eax",
    "0040103E  74 0F           jz      short loc_40104F",
    "00401040  48 8D 0D 39 30  lea     rcx, aDpapi   ; \"DPAPI\"",
    "00401047  E8 24 00 00 00  call    CryptUnprotectData",
    "0040104C  48 8B D8        mov     rbx, rax",
    "0040104F  48 8D 15 12 30  lea     rdx, aLogins  ; \"logins\"",
    "00401056  E8 95 01 00 00  call    sub_4011F0",
    "0040105B  48 85 C0        test    rax, rax",
    "0040105E  74 22           jz      short loc_401082",
    "00401060  48 8B C8        mov     rcx, rax",
    "00401063  E8 78 04 00 00  call    BCryptDecrypt",
    "00401068  85 C0           test    eax, eax",
    "0040106A  78 16           js      short loc_401082",
    "0040106C  48 8B 4C 24 50  mov     rcx, [rsp+50h]",
    "00401071  E8 8A 00 00 00  call    InternetConnectA",
    "00401076  48 89 44 24 40  mov     [rsp+40h], rax",
    "0040107B  E9 73 FE FF FF  jmp     loc_400EF3",
    "00401080  C3              retn",
]

# ---------------------------------------------------------------------------
# Fonts
# ---------------------------------------------------------------------------

FONT_PATHS = {
    "title":  "/System/Library/Fonts/Supplemental/Arial Black.ttf",
    "sans":   "/System/Library/Fonts/Helvetica.ttc",
    "sans_b": "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "mono":   "/System/Library/Fonts/Menlo.ttc",
}

def font(kind: str, size: int):
    path = FONT_PATHS[kind]
    if path.endswith(".ttc"):
        # Helvetica.ttc index 0 = Helvetica, Menlo.ttc index 0 = Menlo Regular
        return ImageFont.truetype(path, size, index=0)
    return ImageFont.truetype(path, size)


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def render():
    img = Image.new("RGB", (W, H), BG)

    # --- Layer 1: hex-dump background, full-bleed, very faint -----------
    bg_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bgd = ImageDraw.Draw(bg_layer)
    mono_small = font("mono", 14)
    line_h = 20
    y = 18
    while y < H:
        line = random.choice(HEX_DUMP_LINES)
        # Fade rows toward bottom for depth.
        fade = max(0.35, 1.0 - (y / H) * 0.55)
        col = tuple(int(c * fade) for c in TEXT_LO) + (int(255 * 0.55),)
        bgd.text((24, y), line, font=mono_small, fill=col)
        y += line_h
    img.paste(bg_layer, (0, 0), bg_layer)

    # --- Layer 2: vignette / gradient panel for legibility ---------------
    grad = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    # Left two-thirds darker so foreground text reads cleanly.
    for x in range(0, int(W * 0.78)):
        # alpha eases out
        a = int(225 * (1.0 - (x / (W * 0.78)) ** 1.4))
        gd.line([(x, 0), (x, H)], fill=(BG[0], BG[1], BG[2], a))
    img.paste(grad, (0, 0), grad)

    d = ImageDraw.Draw(img)

    # --- Accent bar on left ---------------------------------------------
    bar_x = 56
    d.rectangle([bar_x, 90, bar_x + 6, H - 90], fill=ACCENT)

    # --- Prompt tag ------------------------------------------------------
    f_tag = font("mono", 22)
    d.text((bar_x + 28, 92), PROMPT_TAG, font=f_tag, fill=TEXT_MED)
    # Blinking cursor block after the tag
    bbox = d.textbbox((bar_x + 28, 92), PROMPT_TAG, font=f_tag)
    cursor_x = bbox[2] + 8
    d.rectangle([cursor_x, bbox[1] + 4, cursor_x + 12, bbox[3] - 2], fill=TEXT_MED)

    # --- Title -----------------------------------------------------------
    f_title = font("title", 110)
    title_y = 150
    d.text((bar_x + 28, title_y), TITLE, font=f_title, fill=TEXT_HI)

    # Underline accent under title
    tbbox = d.textbbox((bar_x + 28, title_y), TITLE, font=f_title)
    underline_y = tbbox[3] + 14
    d.rectangle(
        [bar_x + 28, underline_y, bar_x + 28 + 180, underline_y + 5],
        fill=ACCENT,
    )

    # --- Subtitle --------------------------------------------------------
    f_sub = font("sans_b", 30)
    d.text((bar_x + 28, underline_y + 28), SUBTITLE, font=f_sub, fill=TEXT_MED)

    # --- Author footer line ---------------------------------------------
    f_auth_label = font("mono", 18)
    f_auth_name  = font("sans_b", 28)
    auth_y = H - 110
    d.text((bar_x + 28, auth_y), "AUTHOR", font=f_auth_label, fill=TEXT_LO)
    d.text((bar_x + 28, auth_y + 22), AUTHOR, font=f_auth_name, fill=TEXT_HI)

    # --- Site URL bottom right ------------------------------------------
    f_url = font("mono", 18)
    url_bbox = d.textbbox((0, 0), SITE_URL, font=f_url)
    url_w = url_bbox[2] - url_bbox[0]
    d.text((W - url_w - 56, H - 60), SITE_URL, font=f_url, fill=TEXT_MED)

    # --- Top-right tag chip ---------------------------------------------
    chip_text = "RE  //  TLP:WHITE"
    f_chip = font("mono", 16)
    cb = d.textbbox((0, 0), chip_text, font=f_chip)
    cw, ch = cb[2] - cb[0], cb[3] - cb[1]
    pad_x, pad_y = 16, 10
    cx2 = W - 56
    cy1 = 56
    cx1 = cx2 - cw - 2 * pad_x
    cy2 = cy1 + ch + 2 * pad_y
    d.rectangle([cx1, cy1, cx2, cy2], outline=BORDER, width=1)
    d.text((cx1 + pad_x, cy1 + pad_y - 2), chip_text, font=f_chip, fill=TEXT_MED)

    # --- Outer 1px border for definition --------------------------------
    d.rectangle([0, 0, W - 1, H - 1], outline=(40, 40, 46), width=1)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    img.save(OUT_PATH, format="PNG", optimize=True)
    print(f"wrote {OUT_PATH}  ({W}x{H})  size={os.path.getsize(OUT_PATH)} bytes")


if __name__ == "__main__":
    random.seed(42)  # deterministic output
    render()
