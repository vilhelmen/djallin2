# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import copy_metadata

block_cipher = None

a = Analysis(['chatdj.py'],
             pathex=[],
             binaries=[],
             datas=[*copy_metadata('djallin2'), ('djallin2/internal/*.mp3', 'djallin2/internal')],
             # Why do you have to ANALYZE. I told you to include it
             # FIXME: websockets.legacy can be removed once their refactor is complete
             hiddenimports=['gtts', 'pyttsx3', 'websockets.legacy', 'websockets.legacy.client'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='chatdj',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          icon='icon.ico')
