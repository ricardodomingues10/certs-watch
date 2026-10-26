"""Gera o logótipo da Atalaia Cert a partir do topo da atalaia já recortado (torre_topo.webp).

    python tools/logo/gerar_svg.py            # escreve certwatch/web/static/atalaia.svg e atalaia-icone.svg

atalaia.svg        o logótipo animado: um vigia (do tronco para cima) com a mão sobre os olhos a tapar o sol,
                   que olha para a direita, depois para a esquerda, e volta. Sem animação quando o sistema
                   pede menos movimento (prefers-reduced-motion).
atalaia-icone.svg  versão quadrada e parada, para o ícone do separador do navegador.

O recorte da fotografia original faz-se com recortar.py (só é preciso repetir com outra fotografia)."""
import base64
import io
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
STATIC = HERE.parents[1] / "certwatch" / "web" / "static"

TW = 100.0          # largura da torre em unidades do viewBox
TOP = 42.0          # onde começa a torre (o vigia fica por cima)
CX = 46.0           # eixo do vigia (centro do topo da torre)

SKIN, SKIN_D, HAIR, SHIRT, SHIRT_D = "#e4b48c", "#c9946b", "#3b2a20", "#4f7396", "#3d5c7a"


def tower(px_per_unit: float, quality: int) -> tuple[str, float]:
    img = Image.open(HERE / "torre_topo.webp").convert("RGBA")
    w = int(TW * px_per_unit)
    img = img.resize((w, int(w * img.height / img.width)), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "WEBP", quality=quality, method=6)
    return base64.b64encode(buf.getvalue()).decode(), TW * img.height / img.width


def figure() -> str:
    """O vigia de perfil, virado para a direita; a animação espelha-o para olhar para a esquerda."""
    c, t = CX, TOP
    return f'''
  <g id="vigia">
    <path d="M{c-11} {t+20} L{c-11} {t-12} Q{c-10} {t-19} {c-4} {t-21} L{c+4} {t-21} Q{c+9} {t-19} {c+10} {t-12} L{c+10} {t+20} Z" fill="{SHIRT}"/>
    <path d="M{c-11} {t+20} L{c-11} {t-12} Q{c-10} {t-19} {c-4} {t-21} L{c-2} {t-21} L{c-5} {t+20} Z" fill="{SHIRT_D}"/>
    <rect x="{c-2.4}" y="{t-26}" width="4.8" height="6.5" rx="1.6" fill="{SKIN_D}"/>
    <g id="cabeca">
      <circle cx="{c+0.5}" cy="{t-31}" r="6.2" fill="{SKIN}"/>
      <path d="M{c+6.4} {t-32.6} l2.3 2.3 l-2.4 0.6 Z" fill="{SKIN}"/>
      <circle cx="{c+3.7}" cy="{t-32.2}" r="0.75" fill="{HAIR}"/>
      <path d="M{c-5.7} {t-29.5} Q{c-7.4} {t-38.6} {c+0.8} {t-38.1} Q{c+6.2} {t-37.7} {c+6.6} {t-34.6} Q{c+1.2} {t-35.4} {c-1.6} {t-31.5} Q{c-3.2} {t-28} {c-5.7} {t-29.5} Z" fill="{HAIR}"/>
    </g>
    <path d="M{c+5} {t-16.5} L{c+13.2} {t-25} L{c+8.6} {t-34.6}" fill="none" stroke="{SHIRT}" stroke-width="4.6" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M{c+12.6} {t-26.4} L{c+8.6} {t-34.6}" fill="none" stroke="{SKIN}" stroke-width="3.3" stroke-linecap="round"/>
    <path d="M{c+3.2} {t-36.5} L{c+12.8} {t-35.7}" fill="none" stroke="{SKIN}" stroke-width="2.7" stroke-linecap="round"/>
  </g>'''


ANIMATION = f'''
  <style>
    #vigia {{ transform-box: view-box; transform-origin: {CX}px 0; animation: olhar 9s ease-in-out infinite; }}
    #cabeca {{ transform-box: view-box; transform-origin: {CX}px {TOP-25}px; animation: procurar 4.5s ease-in-out infinite; }}
    @keyframes olhar {{
      0%, 38% {{ transform: scaleX(1); }}
      46%, 88% {{ transform: scaleX(-1); }}
      96%, 100% {{ transform: scaleX(1); }}
    }}
    @keyframes procurar {{
      0%, 8% {{ transform: rotate(0deg); }}
      22% {{ transform: rotate(-4deg); }}
      36%, 100% {{ transform: rotate(0deg); }}
    }}
    @media (prefers-reduced-motion: reduce) {{ #vigia, #cabeca {{ animation: none; }} }}
  </style>'''


def svg(view_box: str, width: float, height: float, animated: bool, px_per_unit: float, quality: int) -> str:
    data, th = tower(px_per_unit, quality)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" width="{width:g}" height="{height:g}" role="img" aria-label="Atalaia Cert: um vigia no alto de uma atalaia">
  <title>Atalaia Cert</title>{ANIMATION if animated else ""}
  <defs>
    <linearGradient id="esbater" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0.72" stop-color="#fff"/><stop offset="1" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
    <mask id="base"><rect x="0" y="{TOP-1}" width="{TW:g}" height="{th+2:.1f}" fill="url(#esbater)"/></mask>
  </defs>{figure()}
  <image href="data:image/webp;base64,{data}" x="0" y="{TOP}" width="{TW:g}" height="{th:.1f}" mask="url(#base)"/>
</svg>
'''


def main() -> None:
    _, th = tower(0.5, 50)
    h = round(TOP + th, 1)
    (STATIC / "atalaia.svg").write_text(svg(f"0 0 {TW:g} {h}", TW, h, True, 2.4, 82))
    # ícone: quadrado à volta do vigia e do topo da torre, parado e leve
    (STATIC / "atalaia-icone.svg").write_text(svg("6 0 80 80", 80, 80, False, 0.9, 70))
    for n in ("atalaia.svg", "atalaia-icone.svg"):
        print(n, (STATIC / n).stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main()
