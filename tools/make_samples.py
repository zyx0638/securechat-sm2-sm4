"""Create reproducible, non-personal sample media; ffmpeg is only a dev tool."""

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]


def make_image():
    target = ROOT / "samples"
    target.mkdir(exist_ok=True)
    image = Image.new("RGB", (960, 600), "#f2f7f4")
    draw = ImageDraw.Draw(image)
    font_file = Path("C:/Windows/Fonts/arial.ttf")
    large = ImageFont.truetype(str(font_file), 64) if font_file.exists() else ImageFont.load_default()
    small = ImageFont.truetype(str(font_file), 26) if font_file.exists() else ImageFont.load_default()
    draw.rectangle((0, 0, 960, 14), fill="#087f62")
    draw.text((65, 65), "SECURE CHAT", font=large, fill="#203029")
    draw.text((68, 155), "Cryptography laboratory / sample image", font=small, fill="#64736c")
    colors = ["#087f62", "#2784ad", "#d5a12e", "#ce6256"]
    for index, color in enumerate(colors):
        x = 70 + index * 215
        draw.rectangle((x, 260, x + 175, 420), fill=color)
        draw.text((x + 12, 438), ["SM2", "SM3", "SM4", "X25519"][index], font=small, fill="#203029")
    draw.text((68, 530), "Alice  >  encrypted transport  >  Bob", font=small, fill="#203029")
    image.save(target / "sample-image.png")
    (target / "sample-text.txt").write_text("你好，Bob！这是一条用于中级密码学实验的测试消息。\n", encoding="utf-8")
    return target


def main():
    target = make_image()
    import imageio_ffmpeg
    command = [imageio_ffmpeg.get_ffmpeg_exe(), "-y", "-loop", "1", "-i", str(target / "sample-image.png"),
               "-vf", "scale=640:400,drawbox=x=30+100*t:y=330:w=80:h=18:color=white:t=fill",
               "-t", "4", "-r", "20", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
               str(target / "sample-video.mp4")]
    subprocess.run(command, check=True, capture_output=True)
    print("Created image, text and 4-second H.264 video samples.")


if __name__ == "__main__":
    main()
