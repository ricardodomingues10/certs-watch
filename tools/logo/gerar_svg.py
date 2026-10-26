"""Gera o logótipo da Atalaia Cert a partir do topo da atalaia já recortado (torre_topo.webp).

    python tools/logo/gerar_svg.py            # escreve certwatch/web/static/atalaia.svg e atalaia-icone.svg

atalaia.svg        o logótipo animado: uma idosa portuguesa (lenço preto atado ao queixo, roupa preta, xaile),
                   do tronco para cima, com a mão sobre os olhos a tapar o sol, que olha para a direita,
                   depois para a esquerda, e volta. Sem animação quando o sistema
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

def tower(px_per_unit: float, quality: int) -> tuple[str, float]:
    img = Image.open(HERE / "torre_topo.webp").convert("RGBA")
    w = int(TW * px_per_unit)
    img = img.resize((w, int(w * img.height / img.width)), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "WEBP", quality=quality, method=6)
    return base64.b64encode(buf.getvalue()).decode(), TW * img.height / img.width


# a vigia: uma idosa portuguesa de lenço preto atado ao queixo, roupa preta e xaile com franja
SKIN, SKIN_D, BLUSH = "#e3b597", "#c58f73", "#d98d7a"
DRESS, SCARF, SHAWL, SHAWL_D, HAIR = "#2b2930", "#1e1c22", "#55444b", "#45373d", "#d2cdc5"
RIM = "#8a8593"     # contorno claro: a roupa preta não se perde na coluna escura


def figure() -> str:
    """A vigia de perfil, virada para a direita; a animação espelha-a para olhar para a esquerda."""
    c, t = CX, TOP
    rim = f'stroke="{RIM}" stroke-width="0.55" stroke-linejoin="round"'
    fringe = "".join(f'<path d="M{c-11.6+i*2.05:.2f} {t-4.3-i*0.52:.2f} l0.25 2.1" stroke="{SHAWL}" stroke-width="0.75" stroke-linecap="round"/>'
                     for i in range(11))
    return f'''
  <g id="vigia">
    <path d="M{c-12.5} {t+20} L{c-12.5} {t-9} Q{c-12} {t-17.5} {c-5} {t-19.8} L{c+4} {t-19.6} Q{c+10.5} {t-17} {c+11} {t-9} L{c+11.5} {t+20} Z" fill="{DRESS}" {rim}/>
    <path d="M{c-13} {t-3.6} L{c-13} {t-10} Q{c-12.4} {t-18.4} {c-5.2} {t-20.6} L{c+3.6} {t-20.4} Q{c+8.4} {t-18.4} {c+9.6} {t-10.4} Z" fill="{SHAWL}" {rim}/>
    <path d="M{c-13} {t-3.6} L{c-13} {t-10} Q{c-12.4} {t-18.4} {c-5.2} {t-20.6} L{c-3.4} {t-20.6} Q{c-8.6} {t-13} {c-7} {t-5.4} Z" fill="{SHAWL_D}"/>
    <g fill="none">{fringe}</g>
    <g id="cabeca">
      <path d="M{c+6.1} {t-34.8} Q{c+1} {t-39.2} {c-4.6} {t-36.4} Q{c-8.8} {t-32.4} {c-7.8} {t-26.4} Q{c-6.8} {t-22.2} {c-2.6} {t-21.2} L{c+3.4} {t-21.6} Q{c+6.6} {t-22.4} {c+6.9} {t-25.2} Z" fill="{SCARF}" {rim}/>
      <path d="M{c-6.6} {t-24} l-3.4 3.2 l3.6 -0.4 Z" fill="{SCARF}" {rim}/>
      <ellipse cx="{c+3.1}" cy="{t-29.4}" rx="3.7" ry="4.7" fill="{SKIN}"/>
      <path d="M{c+6.3} {t-31.2} q1.9 2.2 0.9 3.1 q-0.7 0.4 -1.3 0.1 Z" fill="{SKIN}"/>
      <path d="M{c+0.4} {t-33.4} Q{c+3.4} {t-35.2} {c+6.1} {t-33.7}" fill="none" stroke="{HAIR}" stroke-width="1.3" stroke-linecap="round"/>
      <circle cx="{c+4.9}" cy="{t-30.4}" r="0.55" fill="{SCARF}"/>
      <path d="M{c+3.4} {t-30.9} l-0.9 -0.4 M{c+3.4} {t-30.1} l-0.9 0.3" stroke="{SKIN_D}" stroke-width="0.35" stroke-linecap="round"/>
      <circle cx="{c+3.6}" cy="{t-27.9}" r="1.1" fill="{BLUSH}" opacity=".45"/>
      <path d="M{c+5.3} {t-26.4} q0.6 0.2 1.1 -0.1" fill="none" stroke="{SKIN_D}" stroke-width="0.45" stroke-linecap="round"/>
      <circle cx="{c+4.6}" cy="{t-22.6}" r="1.25" fill="{SCARF}" {rim}/>
      <path d="M{c+4.4} {t-21.6} l-0.8 2.6 M{c+5} {t-21.6} l1 2.4" stroke="{SCARF}" stroke-width="0.9" stroke-linecap="round"/>
    </g>
    <path d="M{c+3.8} {t-16.6} L{c+12.6} {t-24.6} L{c+9.4} {t-32.4}" fill="none" stroke="{RIM}" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M{c+3.8} {t-16.6} L{c+12.6} {t-24.6} L{c+9.4} {t-32.4}" fill="none" stroke="{DRESS}" stroke-width="4.4" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M{c+10.6} {t-33.2} Q{c+7.6} {t-35.4} {c+3.9} {t-34.6}" fill="none" stroke="{SKIN_D}" stroke-width="2.1" stroke-linecap="round"/>
    <path d="M{c+10.4} {t-33.9} Q{c+7.4} {t-35.9} {c+3.9} {t-35.1}" fill="none" stroke="{SKIN}" stroke-width="1.5" stroke-linecap="round"/>
  </g>'''


ANIMATION = f'''
  <style>
    #vigia {{ transform-box: view-box; transform-origin: {CX}px 0; animation: olhar 9s ease-in-out infinite; }}
    #cabeca {{ transform-box: view-box; transform-origin: {CX}px {TOP-22}px; animation: procurar 4.5s ease-in-out infinite; }}
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
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" width="{width:g}" height="{height:g}" role="img" aria-label="Atalaia Cert: uma idosa de lenço preto vigia do alto de uma atalaia">
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
