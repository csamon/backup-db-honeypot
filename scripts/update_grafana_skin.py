#!/usr/bin/env python3
"""
backup-db-honeypot — Mise à jour du skin Grafana
Télécharge les vrais assets SVG depuis play.grafana.org
et régénère la page de login honeypot.
"""
import urllib.request, base64, os, sys

import sys as _sys
_pyver = f"python{_sys.version_info.major}.{_sys.version_info.minor}"
SKIN_DIR = f"/opt/opencanary/venv/lib/{_pyver}/site-packages/opencanary/modules/data/http/skin/grafanaLogin"
GRAFANA_BASE = "https://play.grafana.org/public/img"

def download(url):
    try:
        return urllib.request.urlopen(url, timeout=10).read()
    except Exception as e:
        print(f"Erreur téléchargement {url}: {e}")
        sys.exit(1)

print("Téléchargement assets Grafana...")
icon_svg = download(f"{GRAFANA_BASE}/grafana_icon.svg").decode()
bg_b64 = base64.b64encode(download(f"{GRAFANA_BASE}/g8_login_dark.svg")).decode()
print("Assets OK")

os.makedirs(SKIN_DIR, exist_ok=True)

HTML = f"""<!DOCTYPE html>
<html lang="en-US"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width">
<title>Grafana</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&display=swap">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:100%}}
body{{font-family:Inter,-apple-system,sans-serif;font-size:14px;color:#d0d5de;min-height:100vh;display:flex;flex-direction:column;background:#111217}}
.bg{{flex:1;display:flex;align-items:center;justify-content:center;padding:24px 16px;background-image:url('data:image/svg+xml;base64,{bg_b64}');background-size:cover;background-position:top center}}
.box{{background:rgba(22,24,29,0.88);border:1px solid rgba(255,255,255,0.07);border-radius:4px;padding:32px 40px 28px;width:100%;max-width:480px;backdrop-filter:blur(8px);box-shadow:0 4px 32px rgba(0,0,0,0.6)}}
.logo{{display:flex;justify-content:center;margin-bottom:16px}}
.logo svg{{width:72px;height:auto}}
h1{{color:#fff;font-size:28px;font-weight:300;text-align:center;margin-bottom:24px;letter-spacing:-0.3px}}
.err{{display:none;background:rgba(224,47,68,0.1);border:1px solid rgba(224,47,68,0.5);border-radius:4px;padding:12px 16px;margin-bottom:16px}}
.err-title{{color:#ff6b6b;font-weight:500;display:flex;align-items:center;gap:8px;margin-bottom:2px}}
.err-body{{color:#d0d5de;font-size:13px;padding-left:22px}}
.f{{margin-bottom:16px}}
label{{display:block;font-size:12px;font-weight:500;color:#9da5b4;margin-bottom:4px}}
.iw{{position:relative}}
input[type=text],input[type=password]{{width:100%;height:32px;padding:6px 12px;background:rgba(11,12,23,0.7);border:1px solid rgba(255,255,255,0.07);border-radius:2px;color:#d0d5de;font-size:14px;font-family:inherit;outline:none;transition:border-color .15s,box-shadow .15s}}
input[type=password]{{padding-right:32px}}
input:focus{{border-color:rgba(87,148,242,0.5);box-shadow:0 0 0 2px rgba(87,148,242,0.12)}}
input::placeholder{{color:#53575f}}
.eye{{position:absolute;right:0;top:0;width:32px;height:32px;background:none;border:none;cursor:pointer;color:#9da5b4;display:flex;align-items:center;justify-content:center;padding:0}}
.eye:hover{{color:#d0d5de}}
.btn{{width:100%;height:32px;background:#3d71d9;border:none;border-radius:2px;color:#fff;font-size:14px;font-weight:500;font-family:inherit;cursor:pointer;margin-top:8px;transition:background .1s}}
.btn:hover{{background:#4d7de0}}
.btn:active{{background:#3262c4}}
.fgt{{text-align:right;margin-top:10px}}
.fgt a{{color:#6c8ebf;font-size:12px;text-decoration:none}}
.fgt a:hover{{text-decoration:underline}}
footer{{background:#181b1f;border-top:1px solid rgba(255,255,255,0.06)}}
.fi{{max-width:960px;margin:0 auto;display:flex;align-items:center;justify-content:center;flex-wrap:wrap;padding:8px 24px;font-size:12px;color:#53575f;gap:0}}
.fi a{{color:#53575f;text-decoration:none;padding:4px 10px;white-space:nowrap}}
.fi a:hover{{color:#9da5b4}}
.fi .sep{{color:#2c3038}}
.fi .ver{{padding:4px 10px;white-space:nowrap}}
</style></head>
<body>
<div class="bg">
  <div class="box">
    <div class="logo">{icon_svg}</div>
    <h1>Welcome to Grafana</h1>
    <div class="err" id="e">
      <div class="err-title"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Login failed</div>
      <div class="err-body">Invalid username or password</div>
    </div>
    <form method="POST" action="" autocomplete="off" onsubmit="document.getElementById('e').style.display='block'">
      <div class="f"><label>Email or username</label><div class="iw"><input type="text" name="username" placeholder="email or username" autofocus></div></div>
      <div class="f"><label>Password</label><div class="iw">
        <input type="password" id="pw" name="password" placeholder="password">
        <button type="button" class="eye" tabindex="-1" onclick="var f=document.getElementById('pw');f.type=f.type=='password'?'text':'password'">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div></div>
      <button type="submit" class="btn">Log in</button>
    </form>
    <div class="fgt"><a href="#">Forgot your password?</a></div>
  </div>
</div>
<footer><div class="fi">
  <a href="#">Documentation</a><span class="sep">|</span>
  <a href="#">Support</a><span class="sep">|</span>
  <a href="#">Community</a><span class="sep">|</span>
  <a href="#">Open Source</a><span class="sep">|</span>
  <span class="ver">Grafana v12.2.1 (563109b696)</span><span class="sep">|</span>
  <a href="#">New version available!</a>
</div></footer>
</body></html>"""

ERR = '''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Grafana</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#111217;color:#9da5b4;font-family:Inter,-apple-system,sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:12px}}.code{{font-size:80px;font-weight:300;color:#3d71d9;line-height:1}}.msg{{color:#53575f;font-size:15px}}a{{color:#6c8ebf;font-size:13px;text-decoration:none;margin-top:8px}}a:hover{{text-decoration:underline}}</style></head><body><div class="code">CODE</div><div class="msg">MSG</div><a href="/">← Back to login</a></body></html>'''

with open(f"{SKIN_DIR}/index.html", "w") as f:
    f.write(HTML)
for fname, (code, msg) in [("400.html",("400","Bad Request")),("403.html",("403","Forbidden")),("404.html",("404","Page Not Found"))]:
    with open(f"{SKIN_DIR}/{fname}", "w") as f:
        f.write(ERR.replace("CODE",code).replace("MSG",msg))
with open(f"{SKIN_DIR}/redirect.html", "w") as f:
    f.write('<html><head><meta http-equiv="refresh" content="0;url=/"></head><body></body></html>')

print(f"Skin Grafana installé dans {SKIN_DIR}")
print("Redémarre opencanary : sudo systemctl restart opencanary")
