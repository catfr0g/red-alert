from __future__ import annotations

import base64
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from red_alert.attacks import AttackScenario

ARTIFACTS_DIR_NAME = "attack_artifacts"
LATEST_IMAGE_NAME = "latest_generated_image.png"
IMAGE_SIZE = (1280, 720)
MARGIN = 64

_FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
)


def default_artifacts_dir() -> Path:
    return Path.cwd() / ARTIFACTS_DIR_NAME


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in _FONT_CANDIDATES:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def _line_height(draw: ImageDraw.ImageDraw, font: ImageFont.ImageFont) -> int:
    bbox = draw.textbbox((0, 0), "Ay", font=font)
    return max(bbox[3] - bbox[1], 1) + 8


def _wrap_paragraph(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.ImageFont,
    max_width: int,
) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        trial = " ".join([*current, word])
        width = draw.textbbox((0, 0), trial, font=font)[2]
        if current and width > max_width:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return lines


def _wrap_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.ImageFont,
    max_width: int,
) -> list[str]:
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        lines.extend(_wrap_paragraph(draw, paragraph, font, max_width))
    return lines or [""]


def render_centered_text(text: str, dest: Path, *, size: tuple[int, int] = IMAGE_SIZE) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    width, height = size
    body = text.strip() or " "
    max_width = width - 2 * MARGIN
    max_height = height - 2 * MARGIN

    font_size = 36
    lines = [body]
    font = _font(font_size)
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    line_h = _line_height(draw, font)
    while font_size >= 16:
        font = _font(font_size)
        draw = ImageDraw.Draw(img)
        lines = _wrap_text(draw, body, font, max_width)
        line_h = _line_height(draw, font)
        if line_h * len(lines) <= max_height:
            break
        font_size -= 4

    total_h = line_h * len(lines)
    y = max((height - total_h) // 2, MARGIN)
    for line in lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        x = (width - (bbox[2] - bbox[0])) // 2
        draw.text((x, y), line, font=font, fill="black")
        y += line_h
    img.save(dest, format="PNG")
    return dest


def image_user_content(
    text: str,
    *,
    caption: str,
    artifacts_dir: Path | None = None,
) -> list[dict]:
    directory = artifacts_dir or default_artifacts_dir()
    path = render_centered_text(text, directory / LATEST_IMAGE_NAME)
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return [
        {"type": "text", "text": caption},
        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded}"}},
    ]


def payload_user_content(scenario: AttackScenario, text: str) -> str | list[dict]:
    if scenario.delivery != "image":
        return text
    return image_user_content(text, caption=scenario.image_caption)
