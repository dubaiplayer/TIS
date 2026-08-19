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
    "auto": None,               # sample the image's own border -- see edge_colour()
    "white": (255, 255, 255),
    "light": (241, 243, 244),   # Gmail/Outlook chrome grey
    "dark": (32, 33, 36),
}


def edge_colour(im):
    """The most common colour around the image's border.

    Padding a dark-theme capture with white frames it in a way that reads as a
    mistake, and mail clients differ in exactly how dark they are -- Outlook's dark
    reading pane and its dark message surface are not the same grey. Sampling the
    border makes the padding continue whatever the capture already had, so the seam
    disappears without anyone having to name a colour.
    """
    w, h = im.size
    px = im.load()
    step = max(1, min(w, h) // 100)
    edge = []
    for x in range(0, w, step):
        edge.append(px[x, 0])
        edge.append(px[x, h - 1])
    for y in range(0, h, step):
        edge.append(px[0, y])
        edge.append(px[w - 1, y])
    counts = {}
    for c in edge:
        counts[c] = counts.get(c, 0) + 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="the raw screenshot (PNG or JPEG)")
    ap.add_argument("--size", default="1280x800",
                    help="target size, 1280x800 (default) or 640x400")
    ap.add_argument("--bg", default="auto", choices=sorted(BACKGROUNDS),
                    help="padding colour; 'auto' (default) matches the image's own edge")
    ap.add_argument("-o", "--out", help="output path (default: <name>-store.png)")
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

    bg = edge_colour(src) if args.bg == "auto" else BACKGROUNDS[args.bg]
    canvas = Image.new("RGB", (tw, th), bg)
    canvas.paste(resized, ((tw - new[0]) // 2, (th - new[1]) // 2))

    out = args.out or (os.path.splitext(args.image)[0] + "-store.png")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    canvas.save(out, "PNG")

    print("in  : %s  (%dx%d)" % (args.image, src.width, src.height))
    print("out : %s  (%dx%d, content %dx%d, padding rgb%s)"
          % (out, tw, th, new[0], new[1], bg))
    if ratio < 1.0:
        print("note: scaled to %.0f%% to fit." % (ratio * 100))
    if new[0] < tw * 0.6 and new[1] < th * 0.6:
        print("note: a lot of padding -- consider a wider capture so the banner "
              "fills more of the frame.")


if __name__ == "__main__":
    main()
