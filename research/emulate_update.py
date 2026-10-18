"""Execute the official x86 update loop against a fake device, without USB or Wine.

Requires pefile and unicorn from the adjacent research venv. All Windows/UI calls
are explicit stubs. Only the actual updater's control flow/payload copying runs.
"""
import hashlib
import json
import struct
import argparse
from pathlib import Path

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EAX

ROOT = Path(__file__).resolve().parent
EXE = ROOT.parent / "artifacts/research/GuliKit_NS38_NS39_NS59_BT_V5.07.exe"
EXPECTED_EXE = "3dc8fd352597de4b619efcf139933fbbccc5c1c335aa580455bf5f64f4b9c97a"


def emulate(first_error=0, final_error=0):
    require(hashlib.sha256(EXE.read_bytes()).hexdigest() == EXPECTED_EXE, "not the reviewed executable")
    pe = pefile.PE(str(EXE))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    image = pe.get_memory_mapped_image()
    u.mem_map(0x400000, (max(len(image), pe.OPTIONAL_HEADER.SizeOfImage) + 4095) & ~4095)
    u.mem_write(0x400000, image)
    u.mem_map(0x1000000, 0x20000)
    u.mem_map(0x2000000, 0x10000)
    u.mem_map(0x3000000, 0x1000)
    ebp = 0x1010000
    obj = 0x2000000
    u.reg_write(UC_X86_REG_EBP, ebp)
    u.reg_write(UC_X86_REG_ESP, ebp - 0x400)
    u.reg_write(UC_X86_REG_ESI, obj)
    u.reg_write(UC_X86_REG_EDI, obj + 0x1000)

    def put(address, value):
        u.mem_write(address, struct.pack("<I", value))

    def get(address):
        return struct.unpack("<I", u.mem_read(address, 4))[0]

    length = get(0x5732E4)
    original = bytes(u.mem_read(0x5732F0, length))
    original_view = memoryview(original)
    identity = bytes(u.mem_read(0x5732D0, 16))
    put(ebp - 0x2BC, length)
    put(ebp - 0x2B4, obj + 0x1000)
    put(ebp - 0x30, 0xF0)
    put(ebp - 0x28, 0xF1)
    put(ebp - 0x18, 0xF2)
    put(0x5F985C, 4)  # synthetic E: drive index, as expected by official loop
    stubs = {0x3000000: ("open", 0), 0x3000010: ("request", 0), 0x3000020: ("close", 0), 0x3000030: ("drives", 0), 0x3000040: ("sendmessage", 16)}
    for slot, target in [(0x5F9870, 0x3000000), (0x5F9864, 0x3000010), (0x5F986C, 0x3000020), (0x52740C, 0x3000030), (0x527828, 0x3000040)]:
        put(slot, target)
    for address, pops in [(0x40A96E, 0), (0x40A959, 0), (0x401BF0, 0), (0x40EB01, 12), (0x40ED98, 4), (0x401D50, 0), (0x503B50, 0)]:
        stubs[address] = ("memcpy" if address == 0x503B50 else "ui", pops)
    calls = []
    write_count = 0
    streamed_length = 0
    stream_matches_payload = True
    outcome = {"exit_va": None}

    def hook(cpu, address, size, userdata):
        nonlocal write_count, streamed_length, stream_matches_payload
        if address in (0x4029B1, 0x402965, 0x4028FC, 0x4029BF, 0x402721):
            outcome["exit_va"] = hex(address)
            cpu.emu_stop()
            return
        if address not in stubs:
            if not 0x4025CD <= address < 0x402A33:
                raise RuntimeError(f"Unexpected unmocked execution {address:#x}")
            return
        name, pops = stubs[address]
        sp = cpu.reg_read(UC_X86_REG_ESP)
        args = [get(sp + 4 + i * 4) for i in range(6)]
        retval = 6 if address == 0x40EB01 else 1
        if name == "drives":
            retval = 1 << 4
        elif name == "memcpy":
            dst, src, n = args[:3]
            cpu.mem_write(dst, bytes(cpu.mem_read(src, n)))
            retval = dst
        elif name == "request":
            handle, direction, cdbptr, cdblen, data, n = args
            cdb = bytes(cpu.mem_read(cdbptr, cdblen))
            calls.append({"opcode": hex(cdb[0]), "direction": direction, "cdb_len": cdblen, "data_len": n})
            if cdb[0] == 0xF1:
                require(direction == 1 and n == 20, "invalid F1 request")
                cpu.mem_write(data, identity + struct.pack("<HH", 331, 0))
            elif cdb[0] == 0xF0:
                require(direction == 0 and 0 < n <= 512, "invalid F0 request")
                chunk = bytes(cpu.mem_read(data, n))
                expected = original_view[streamed_length:streamed_length + n]
                stream_matches_payload = stream_matches_payload and chunk == expected
                write_count += 1
                streamed_length += len(chunk)
            elif cdb[0] == 0xF2:
                require(direction == 1 and n == 20, "invalid F2 request")
                status = first_error if write_count == 1 else final_error
                cpu.mem_write(data, bytes([status]) + bytes(19))
            else:
                raise RuntimeError(f"Unexpected CDB: {cdb.hex()}")
        cpu.reg_write(UC_X86_REG_EAX, retval)
        cpu.reg_write(UC_X86_REG_EIP, get(sp))
        cpu.reg_write(UC_X86_REG_ESP, sp + 4 + pops)

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(0x4025CD, 0x402A33, count=2000000)
    stream_matches_payload = stream_matches_payload and streamed_length == len(original)
    outcome.update(payload_length=length, write_count=write_count, streamed_length=streamed_length, stream_matches_payload=stream_matches_payload, payload_sha256=hashlib.sha256(original).hexdigest(), first_calls=calls[:3], last_call=calls[-1] if calls else None)
    return outcome


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_results(runs):
    require(runs == json.loads((ROOT / "emulation-results.json").read_text()), "official-loop baseline diverged")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=EXE, help="hash-pinned official EXE; never executed natively")
    EXE = parser.parse_args().exe
    runs = {"success": emulate(), "first_status_error": emulate(first_error=7), "final_status_error": emulate(final_error=7)}
    validate_results(runs)
    print(json.dumps(runs, indent=2))
