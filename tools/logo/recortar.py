"""Recorta a atalaia da fotografia (céu azul) e guarda o topo em torre_topo.webp.
As constantes (linhas de corte, ponto de partida) são desta fotografia; com outra fotografia é preciso ajustá-las.

    python tools/logo/recortar.py torre.jpg && python tools/logo/gerar_svg.py
"""
from pathlib import Path
from PIL import Image, ImageFilter
import numpy as np
from collections import deque
src=Image.open(__import__('sys').argv[1] if len(__import__('sys').argv) > 1 else 'torre.jpg').convert('RGB'); im=np.asarray(src).astype(int)
H,W,_=im.shape
r,g,b=im[...,0],im[...,1],im[...,2]
sky=(b>r+35)&(b>g+5)&(b>110)
TOP, FIT0, FIT1, BASE = 560, 1450, 1820, 2195
mask=np.zeros((H,W),bool)
mask[TOP:FIT1, 600:1290] = ~sky[TOP:FIT1, 600:1290]
for y in range(TOP, 640):                       # poste do topo
    xs=np.where(mask[y])[0]
    if len(xs) and xs.max()-xs.min() < 60: mask[y]=False
start=(1300, 940); q=deque([start]); keep=np.zeros_like(mask); keep[start]=True
while q:
    y,x=q.popleft()
    for dy,dx in ((1,0),(-1,0),(0,1),(0,-1)):
        ny,nx=y+dy,x+dx
        if 0<=ny<H and 0<=nx<W and mask[ny,nx] and not keep[ny,nx]:
            keep[ny,nx]=True; q.append((ny,nx))
mask=keep
yy=np.arange(FIT0, FIT1)
L=np.array([np.where(mask[y])[0].min() for y in yy]); R=np.array([np.where(mask[y])[0].max() for y in yy])
pl=np.polyfit(yy,L,1); pr=np.polyfit(yy,R,1)
for y in range(FIT1, BASE):
    l=int(round(np.polyval(pl,y))); rr=int(round(np.polyval(pr,y)))
    mask[y,:]=False; mask[y,l:rr+1]=True
mask[BASE:]=False
a=Image.fromarray((mask*255).astype(np.uint8)).filter(ImageFilter.MinFilter(3)).filter(ImageFilter.GaussianBlur(1.2))
alpha=np.asarray(a).astype(float)
out=im.astype(float)
edge=(alpha>0)&(alpha<250)
out[...,2][edge]=np.minimum(out[...,2][edge], (out[...,0][edge]+out[...,1][edge])/2)
img=Image.fromarray(np.dstack([out.clip(0,255), alpha]).astype(np.uint8),'RGBA')
img=img.crop(img.getbbox())
top=img.crop((0,0,img.width,int(img.height*0.48)))            # só o topo da torre entra no logótipo
top=top.resize((240,int(240*top.height/top.width)),Image.LANCZOS)
top.save(Path(__file__).resolve().parent/'torre_topo.webp',quality=92,method=6); print(top.size)
