"""Convert a raw screenshot into a Chrome Web Store listing image.

The store accepts screenshots at exactly 1280x800 or 640x400. A screenshot straight
from Snipping Tool is almost never either, and a wrong size is rejected at upload.

This scales the image to fit inside 1280x800 without distorting it, then pads the
remainder with a neutral background, so nothing is stretched or cropped away.

    .venv\\Scripts\\python.exe scripts/make_store_screenshot.py shot.png
    .venv\\Scripts\\python.exe scripts/make_store_screenshot.py shot.png --bg white
    .venv\\Scripts\\python.exe scripts/make_store_screenshot.py shot.png --size 640x400

Writes <name>-store.png next to the input.
"""

import argparse
import os
import sys

try:
    from PIL import Image
except ImportError:
    sys.exit("Pillow is missing. Run this with the project venv:\n"
             "  .venv\\Scripts\\python.exe scripts/make_store_screenshot.py <file>")

BACKGROUNDS = {
    "white": (255, 255, 255),
    "light": (241, 243, 244),   # Gmail/Outlook chrome grey
    "dark": (32, 33, 36),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="the raw screenshot (PNG or JPEG)")
    ap.add_argument("--size", default="1280x800",
                    help="target size, 1280x800 (default) or 640x400")
    ap.add_argument("--bg", default="light", choices=sorted(BACKGROUNDS),
                    help="padding colour (default: light)")
    args = ap.parse_args()

    if args.size not in ("1280x800", "640x400"):
        sys.exit("The store accepts only 1280x800 or 640x400.")
    tw, th = (int(v) for v in args.size.split("x"))

    if not os.path.exists(args.image):
        sys.exit("No such file: " + args.image)

    src = Image.open(args.image).convert("RGB")
    if src.size == (tw, th):
        print("Already %dx%d -- nothing to do." % (tw, th))
        return

    # Scale to fit, never up past 1:1 -- upscaling a small crop just looks blurry in
    # the listing, and the store cares about the canvas size, not the content size.
    ratio = min(tw / src.width, th / src.height, 1.0)
    new = (max(1, round(src.width * ratio)), max(1, round(src.height * ratio)))
    resized = src.resize(new, Image.LANCZOS)

    canvas = Image.new("RGB", (tw, th), BACKGROUNDS[args.bg])
    canvas.paste(resized, ((tw - new[0]) // 2, (th - new[1]) // 2))

    root, _ = os.path.splitext(args.image)
    out = root + "-store.png"
    canvas.save(out, "PNG")

    print("in  : %s  (%dx%d)" % (args.image, src.width, src.height))
    print("out : %s  (%dx%d, content %dx%d, %s padding)"
          % (out, tw, th, new[0], new[1], args.bg))
    if ratio < 1.0:
        print("note: scaled to %.0f%% to fit." % (ratio * 100))
    if new[0] < tw * 0.6 and new[1] < th * 0.6:
        print("note: a lot of padding -- consider a wider capture so the banner "
              "fills more of the frame.")


if __name__ == "__main__":
    main()
