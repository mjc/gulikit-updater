"""Prepare hash-checked official artifacts for offline instruction emulation.

Only the known Bluetooth 5.07 ZIP is accepted. No vendor executable is launched
and no device APIs are used. Outputs belong in the ignored research cache.
"""
import argparse
import hashlib
import io
from pathlib import Path
from zipfile import ZipFile

import pefile

EXE_NAME = "GuliKit_NS38_NS39_NS59_BT_V5.07.exe"
ZIP_SHA = "6ce3db166031d30ff9f61e83387c6f8cb0475eef57321c2347ee32afe9152dad"
EXE_SHA = "3dc8fd352597de4b619efcf139933fbbccc5c1c335aa580455bf5f64f4b9c97a"
PAYLOAD_SHA = "2e0e89d458eb39f30eaa1ba9f4038039ad95c2eeed0e392ecfb0d5ece3441826"
DLL_SHA = "fad660bc7e006c58f37db9d75b72bf30c089ef62fc4e72673cbfd424d247b5e5"


def checked(data, size, digest):
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("artifact does not match the reviewed official release")
    return data


def prepare(archive, output):
    with archive.open("rb") as source:
        original = checked(source.read(1_148_145), 1_148_144, ZIP_SHA)
    with ZipFile(io.BytesIO(original)) as package:
        with package.open(EXE_NAME) as source:
            exe = checked(source.read(2_245_633), 2_245_632, EXE_SHA)
    pe = pefile.PE(data=exe)
    payload = checked(pe.get_data(0x1732F0, 345_088), 345_088, PAYLOAD_SHA)
    dlls = [
        pe.get_data(language.data.struct.OffsetToData, language.data.struct.Size)
        for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries
        if str(resource.name) == "IDR_DLL"
        for item in resource.directory.entries
        if item.id == 0x82
        for language in item.directory.entries
    ]
    if len(dlls) != 1:
        raise ValueError("ambiguous embedded DeviceUsb.dll")
    dll = checked(dlls[0], 8_704, DLL_SHA)
    output.mkdir(parents=True, exist_ok=True)
    for name, data in [(EXE_NAME, exe), ("bt-v5.07-payload.bin", payload), ("DeviceUsb.official.dll", dll)]:
        destination = output / name
        destination.write_bytes(data)
        print(f"{destination}: {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, default=root / "artifacts/research")
    args = parser.parse_args()
    prepare(args.archive, args.output)
