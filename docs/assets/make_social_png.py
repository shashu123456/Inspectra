"""Generate assets/social-preview.png (1280x640) from the same design as social-preview.svg."""

from __future__ import annotations

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (10, 10, 10)
CARD = (20, 20, 20)
ACCENT = (6, 182, 214)  # #06b6d4
TEXT = (234, 234, 234)
MUTED = (156, 163, 175)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# subtle scan rings
d.ellipse((20, 20, 340, 340), outline=ACCENT, width=2)
# mark card
d.rounded_rectangle((90, 90, 550, 550), radius=24, fill=CARD)
d.ellipse((250, 250, 430, 430), outline=ACCENT, width=7)
d.ellipse((294, 294, 366, 366), outline=ACCENT, width=5)
d.line((340, 340, 400, 400), fill=ACCENT, width=6)
d.ellipse((310, 310, 330, 330), fill=ACCENT)
# wordmark
try:
    f_big = ImageFont.truetype("Consolas.ttf", 128)
    f_small = ImageFont.truetype("Consola.ttf", 24)
except Exception:
    f_big = ImageFont.load_default()
    f_small = ImageFont.load_default()
d.text((590, 300), "inspectra", font=f_big, fill=TEXT)
d.line((590, 345, 1110, 345), fill=ACCENT, width=6)
d.text(
    (590, 415),
    "Passive security assessment  ·  SSRF-safe  ·  Deterministic replay",
    font=f_small,
    fill=MUTED,
)
d.text((590, 465), "inspectra-cli  ·  PyPI  ·  GitHub Actions", font=f_small, fill=MUTED)

img.save("assets/social-preview.png")
print("wrote assets/social-preview.png", img.size)
