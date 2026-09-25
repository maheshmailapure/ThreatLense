# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['installer_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/shivl/Documents/Antigravity Projects/installer/threatlense.ico', '.'), ('C:/Users/shivl/Documents/Antigravity Projects/installer/threatlense_logo.png', '.'), ('C:/Users/shivl/Documents/Antigravity Projects/installer/payload.zip', '.')],
    hiddenimports=['PIL', 'PIL.Image', 'PIL.ImageTk'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ThreatLense-Setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:/Users/shivl/Documents/Antigravity Projects/installer/threatlense.ico'],
)
