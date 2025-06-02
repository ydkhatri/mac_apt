# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['..\\mac_apt_artifact_only.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('..\\plugins', 'plugins'), 
        ('..\\plugin.py', '.'),
        ('..\\version.py', '.')
    ],
    hiddenimports=[
        'plistutils.alias',
        'PIL',
        'PIL.Image',
        'zoneinfo'
    ],
    hookspath=['.\\'],
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
    [
        ('W ignore::DeprecationWarning', None, 'OPTION'),
        ('W ignore::UserWarning', None, 'OPTION')
    ],
    a.binaries,
    a.datas,
    [],
    name='mac_apt_artifact_only',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='mac_apt_artifact_only_version_info.txt',
)
