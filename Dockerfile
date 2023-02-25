FROM python:3.9

RUN pip install anytree biplist construct==2.9.45 xlsxwriter plistutils kaitaistruct lz4 pytsk3==20170802 libvmdk-python==20181227 pycryptodome cryptography pybindgen==0.21.0 pillow pyliblzfse nska_deserialize
RUN pip install https://github.com/libyal/libewf-legacy/releases/download/20140808/libewf-20140808.tar.gz
RUN pip install https://github.com/ydkhatri/mac_apt/raw/master/other_dependencies/pyaff4-0.31-yk.zip

WORKDIR /app
COPY . ./
ENTRYPOINT ["python"]
