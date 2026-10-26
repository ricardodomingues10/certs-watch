"""Gera o ícone do separador do navegador (certwatch/web/static/atalaia-icone.svg) a partir do logótipo.

    python tools/logo/gerar_svg.py

O logótipo é desenhado em certwatch/web/templates/_atalaia.html (SVG inline: uma idosa de lenço preto, com a mão em
pala sobre os olhos e um foco na outra mão, no alto de uma atalaia em desenho) e animado em style.css (classes atl-*).
O ícone é o mesmo desenho, parado e recortado em quadrado à volta da vigia e do topo da torre."""
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "certwatch" / "web" / "templates"
OUT = ROOT / "certwatch" / "web" / "static" / "atalaia-icone.svg"


def main() -> None:
    env = Environment(loader=FileSystemLoader(TEMPLATES))
    svg = env.from_string('{% from "_atalaia.html" import atalaia %}{{ atalaia("i", "", "parado") }}').render()
    svg = svg.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" ', 1)
    svg = re.sub(r'viewBox="[^"]*"', 'viewBox="24 12 72 72"', svg, count=1)
    svg = re.sub(r"\n\s*\n", "\n", svg)
    OUT.write_text(svg.strip() + "\n")
    print(OUT.relative_to(ROOT), OUT.stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main()
