You will need to copy the .pyd files contained here into your python 
installation folder under Lib\site-packages\

This is specific for Python 3.7 and will not work with other versions. It is
also specific to your platform (32/64 bits). 

The 32-bit versions are located in the 32bit_py37 folder. 
The 64-bit versions are located in the 64bit_py37 folder. 

Copy only the files for your platform into Lib\site-packages\

If you are unsure about your python platform (32/64), then run python.exe and 
run the following 2 lines of code:

 import sys
 sys.maxsize > 2**32

If the reply is True, you are on 64 bit python, else 32 bit.

The .pyd files are DLLs that have been compiled using Visual Studio 2017. 
These files are dependencies that need to be installed for mac_apt to run on
Windows (when running from code). 

pyewf.pyd  -> https://github.com/libyal/libewf
pytsk3.pyd -> https://github.com/py4n6/pytsk
pyvmdk.pyd -> https://github.com/libyal/libvmdk
lzfse.pyf  -> https://github.com/ydkhatri/pylzfse

lzfse.pyd is a fork of the pylzfse project (https://github.com/dimkr/pylzfse) with 
a few modifications to work with the compression parameters used in macOS. That 
project in turn depends on Apple's reference implementation of lzvn/lzfse available
at https://github.com/lzfse/lzfse.
