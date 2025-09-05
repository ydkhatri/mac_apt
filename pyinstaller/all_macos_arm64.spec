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
b = Analysis(
    ['../mac_apt_artifact_only.py'],
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
c = Analysis(
    ['../ios_apt.py'],
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

a_pyz = PYZ(a.pure)
b_pyz = PYZ(b.pure)
c_pyz = PYZ(c.pure)

a_exe = EXE(
    a_pyz,
    a.scripts,
    [
        ('W ignore::DeprecationWarning', None, 'OPTION'),
        ('W ignore::UserWarning', None, 'OPTION')
    ],
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
b_exe = EXE(
    b_pyz,
    b.scripts,
    [
        ('W ignore::DeprecationWarning', None, 'OPTION'),
        ('W ignore::UserWarning', None, 'OPTION')
    ],
    [],
    exclude_binaries=True,
    name='mac_apt_artifact_only',
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
c_exe = EXE(
    c_pyz,
    c.scripts,
    [
        ('W ignore::DeprecationWarning', None, 'OPTION'),
        ('W ignore::UserWarning', None, 'OPTION')
    ],
    [],
    exclude_binaries=True,
    name='ios_apt',
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
    a_exe, b_exe, c_exe,
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
    version='1.26.8'
)