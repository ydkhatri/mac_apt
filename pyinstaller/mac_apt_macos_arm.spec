# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['../mac_apt.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../plugins', 'plugins'), 
        ('../plugin.py', '.'),
        ('../version.py', '.')
    ],
    hiddenimports=[
        'plistutils.alias',
        'PIL',
        'PIL.Image',
        'zoneinfo'
    ],
    hookspath=['./'],
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
    [],
    [],
    exclude_binaries=True,
    name='mac_apt',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="arm64",
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='mac_apt_arm64',
)
app = BUNDLE(
    coll,
    name='mac_apt_arm64.app',
    bundle_identifier='com.swiftforensics.macapt',
    version='1.26.1'
)