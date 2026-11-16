from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (10, 10, 10)
CARD = (16, 16, 16)
ACCENT = (6, 182, 214)   # #06b6d4
TEXT = (234, 234, 234)
MUTED = (156, 163, 175)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# mark (left), SVG translate(90, 200) -> absolute origin (90, 200)
d.rectangle((90, 200, 390, 500), fill=CARD)
mx, my = 240, 350  # (90+150, 200+150)
d.ellipse((mx - 84, my - 84, mx + 84, my + 84), outline=ACCENT, width=32)
d.ellipse((mx - 20, my - 20, mx + 20, my + 20), fill=ACCENT)

# wordmark "inspectra"
f_big = ImageFont.truetype("consola.ttf", 112)
d.text((420, 400 - 112), "inspectra", font=f_big, fill=TEXT)

# pitch line
f_small = ImageFont.truetype("consola.ttf", 28)
d.text((420, 560 - 28), "Passive security assessment · SSRF-safe", font=f_small, fill=MUTED)

img.save("assets/social-preview.png")
print("wrote assets/social-preview.png", img.size)
