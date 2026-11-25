# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: Windows GUI pathprobe-gui.exe

from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = []
binaries = []
hiddenimports = [
    "dns",
    "dns.message",
    "dns.query",
    "dns.rcode",
    "dns.rdatatype",
    "dns.exception",
    "yaml",
    "pathprobe",
    "pathprobe.gui",
    "pathprobe.gui.app",
    "pathprobe.diagnose",
    "pathprobe.diagnose.runner",
    "pathprobe.report",
]

for pkg in ("customtkinter", "dns"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    ["pathprobe/gui/__main__.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="pathprobe-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
