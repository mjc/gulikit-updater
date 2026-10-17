"""Offline vendor x86 discovery/prelude + actual embedded DeviceUsb DLL.
All deviceUsb exports execute unmodified. Windows/CRT imports are mocked.
MFC UI wrappers execute. Two static pure CRT text-format routines remain explicit
runtime boundaries, alongside Windows/CRT imported functions.
"""
from pathlib import Path
import argparse, hashlib, json, struct
from emulate_update import require
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'artifacts/research/windows-context'
EXE = ROOT / 'artifacts/research/GuliKit_NS38_NS39_NS59_BT_V5.07.exe'
DLL = ROOT / 'artifacts/research/DeviceUsb.official.dll'
UI = {}
CRT_FORMAT = {5252912: '_vscwprintf', 5252519: 'vswprintf'}

def read_reference(path, size, digest, label):
    with path.open('rb') as source:
        data = source.read(size + 1)
    require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, f'not the reviewed {label}')
    return data

def emulate(kind='expected', failures=0, *, exe=EXE, dll=DLL, output=OUTPUT):
    EXE, DLL, R = (Path(exe), Path(dll), Path(output))
    images = [('EXE', read_reference(EXE, 2245632, '3dc8fd352597de4b619efcf139933fbbccc5c1c335aa580455bf5f64f4b9c97a', 'executable')), ('DLL', read_reference(DLL, 8704, 'fad660bc7e006c58f37db9d75b72bf30c089ef62fc4e72673cbfd424d247b5e5', 'DLL'))]
    R.mkdir(parents=True, exist_ok=True)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(0, 4096)
    pes = []
    for name, image in images:
        pe = pefile.PE(data=image)
        base = pe.OPTIONAL_HEADER.ImageBase
        im = pe.get_memory_mapped_image()
        u.mem_map(base, max(len(im), pe.OPTIONAL_HEADER.SizeOfImage) + 4095 & ~4095)
        u.mem_write(base, im)
        pes.append((name, pe))
    u.mem_map(16777216, 262144)
    u.mem_write(16777216, b'\xa5' * 262144)
    u.mem_map(33554432, 4194304)
    u.mem_map(50331648, 65536)
    u.mem_write(50397168, b'\xcc')

    def put(a, n):
        u.mem_write(a, struct.pack('<I', n & 4294967295))

    def get(a):
        return struct.unpack('<I', u.mem_read(a, 4))[0]

    def astr(a):
        out = bytearray()
        while (c := bytes(u.mem_read(a + len(out), 1)))[0]:
            out += c
        return bytes(out)

    def wstr(a):
        b = bytearray()
        while (c := bytes(u.mem_read(a + len(b), 2))) != b'\x00\x00':
            b += c
        return b.decode('utf-16le')
    imports = {}
    offset = 0
    for module, pe in pes:
        for d in pe.DIRECTORY_ENTRY_IMPORT:
            for i in d.imports:
                address = 50331648 + offset
                offset += 16
                imports[address] = (i.name.decode() if i.name else str(i.ordinal), module)
                put(i.address, address)
    exports = {e.name.decode(): e.address + 268435456 for e in pes[1][1].DIRECTORY_ENTRY_EXPORT.symbols}
    for slot, name in [(6264944, 'deviceUsb_OpenByDrv'), (6264936, 'deviceUsb_GetInfo'), (6264940, 'deviceUsb_Close'), (6264932, 'deviceUsb_Request')]:
        put(slot, exports[name])
    put(6263268, 1)
    obj = 33554432
    put(obj, 5578356)
    put(obj + 188, 1)
    put(6264924, 255)
    put(obj + 196 + 32, 1280)
    put(obj + 228, 1280)
    put(6239640, 1)
    put(6246392, 33619968)
    put(33619968, 5)
    put(33619980, 4)
    put(33624072, 4)
    put(33624076, 33624320)
    put(33624324, 33628160)
    put(33628164, 33630208)
    put(33630212, 33632256)
    put(33632256, 5407492)
    put(6246516, 2457)
    put(6249948, 1)
    put(6250392, 1)
    put(33630324, 2)
    put(33624328, 33636352)
    put(33636372, 33640448)
    put(33640480, 33644544)
    put(33640484, 1)
    put(33644544, 33644800)
    put(33644804, 1280)
    put(33644808, 33648640)
    put(33648672, 1280)
    heap = 34603008
    allocs = {}
    events = []
    instructions = 0
    phase = 'discovery'
    clock = 0
    handle = 40
    io_calls = 0
    close_calls = 0
    stop_reason = ''
    flag_writes = []
    recent = []
    pending_deadline = None
    worker_context = None
    worker_fs = 0
    writes = []
    f2_count = 0
    ui_pump_count = 0
    ui_update_count = 0

    def alloc(n, old=0):
        nonlocal heap
        n = max(n, 16)
        ptr = heap
        heap += n + 15 & ~15
        u.mem_write(ptr, bytes(n))
        allocs[ptr] = n
        if old and old in allocs:
            u.mem_write(ptr, bytes(u.mem_read(old, min(n, allocs[old]))))
        return ptr

    def descriptor():
        if kind.startswith('expected'):
            parts = [b'Gamepad ', b'Updater         ', b'1.00']
        elif kind == 'raw_utf16_guli':
            parts = [b'G\x00u\x00l\x00i\x00', b'', b'']
        else:
            parts = [b'Guli', b'', b'']
        b = bytearray(40)
        struct.pack_into('<II', b, 0, 40, 40)
        for o, s in zip([12, 16, 20], parts):
            struct.pack_into('<I', b, o, len(b))
            b.extend(s + b'\x00')
        struct.pack_into('<I', b, 28, 3 if kind == 'non_usb' else 7)
        struct.pack_into('<I', b, 4, len(b))
        return bytes(b)

    def ret(sp, pop, value):
        u.reg_write(UC_X86_REG_EAX, value & 4294967295)
        u.reg_write(UC_X86_REG_EIP, get(sp))
        u.reg_write(UC_X86_REG_ESP, sp + 4 + pop)

    def hook(cpu, a, n, data):
        nonlocal instructions, clock, handle, io_calls, close_calls, stop_reason, pending_deadline, f2_count, ui_pump_count, ui_update_count
        instructions += 1
        recent.append(hex(a))
        recent[:] = recent[-30:]
        if a == 4201808:
            ui_pump_count += 1
            events.append({'kind': 'actual_UI_pump', 'va': hex(a), 'index': ui_pump_count})
        if a == 4255128:
            ui_update_count += 1
            events.append({'kind': 'actual_UI_update', 'va': hex(a), 'index': ui_update_count})
        if a == 50397168:
            stop_reason = 'function_return'
            cpu.emu_stop()
            return
        if a == 4205912:
            events.append({'kind': 'GetInfo_return', 'return': cpu.reg_read(UC_X86_REG_EAX), 'synthetic_descriptor_output': wstr(cpu.reg_read(UC_X86_REG_EBP) - 176) if cpu.reg_read(UC_X86_REG_EAX) else None})
        if a == 4204106:
            events.append({'kind': 'F1_return', 'return': cpu.reg_read(UC_X86_REG_EAX), 'response_buffer_hex': bytes(cpu.mem_read(cpu.reg_read(UC_X86_REG_EBP) - 176, 20)).hex()})
        if a == 4204241:
            events.append({'kind': 'identity_comparison', 'matched_prefix_bytes': cpu.reg_read(UC_X86_REG_EAX)})
        if a == 4203892:
            events.append({'kind': 'prelude', 'event': 'discovery_disable_instruction', 'flag_before': bytes(cpu.mem_read(obj + 188, 1)).hex()})
        if a in exports.values():
            events.append({'kind': 'actual_vendor_export', 'name': next((k for k, v in exports.items() if v == a)), 'va': hex(a), 'phase': phase})
        sp = cpu.reg_read(UC_X86_REG_ESP)
        if a in CRT_FORMAT:
            import re
            args = [get(sp + 4 + i * 4) for i in range(4)]
            fmt, va = args[:2] if a == 5252912 else args[2:4]
            f = wstr(fmt)
            count = len(re.findall('%[-+ #0\\d.]*[du]', f))
            values = tuple((get(va + 4 * i) for i in range(count)))
            text = f % values if count else f
            if a == 5252519:
                cpu.mem_write(args[0], (text + '\x00').encode('utf-16le'))
            events.append({'kind': 'static_CRT_format_boundary', 'name': CRT_FORMAT[a], 'format': f, 'text': text, 'phase': phase})
            ret(sp, 0, len(text))
            return
        if a in UI:
            name, pop = UI[a]
            events.append({'kind': 'UI_boundary', 'name': name, 'va': hex(a), 'phase': phase})
            ret(sp, pop, 6 if name == 'MFC_MessageBox' else obj + 4096 if name == 'MFC_GetDlgItem' else 1)
            return
        if a not in imports:
            return
        name, module = imports[a]
        args = [get(sp + 4 + i * 4) for i in range(9)]
        value = 1
        pop = 0
        event = {'kind': 'import', 'name': name, 'module': module, 'phase': phase, 'virtual_time_ms': clock}
        if name in ['GetLogicalDrives']:
            value = 1 << 4
        elif name in ['EnterCriticalSection', 'LeaveCriticalSection', 'InitializeCriticalSection']:
            pop = 4
        elif name == 'TlsGetValue':
            pop = 4
            value = 33624064
        elif name == 'SetCursor':
            pop = 4
            value = 2184
            event['cursor_handle'] = hex(args[0])
        elif name == 'GetDlgItem':
            pop = 8
            value = 1280
        elif name == 'GetParent':
            pop = 4
            value = 0
        elif name == 'EnableWindow':
            pop = 8
            value = 1
        elif name == 'ActivateActCtx':
            pop = 8
            value = 1
            put(args[1], 123)
        elif name == 'DeactivateActCtx':
            pop = 8
            value = 1
        elif name == 'MessageBoxW':
            pop = 16
            value = 6
            event.update(text=wstr(args[1]), caption=wstr(args[2]), flags=hex(args[3]))
        elif name == 'SetLastError':
            pop = 4
        elif name == 'SendMessageW':
            pop = 16
            value = 0
            event.update(hwnd=args[0], message=hex(args[1]), wparam=args[2], lparam=args[3])
        elif name == 'PeekMessageW':
            pop = 20
            value = 0
        elif name == 'GetDriveTypeW':
            value = 2
            pop = 4
            event['path'] = wstr(args[0])
        elif name in ['MultiByteToWideChar', 'WideCharToMultiByte']:
            cp, flags, src, count, dst, cap = args[:6]
            wide = name == 'WideCharToMultiByte'
            text = (wstr(src) if count == 4294967295 else bytes(cpu.mem_read(src, count * 2)).decode('utf-16le')) if wide else (astr(src) if count == 4294967295 else bytes(cpu.mem_read(src, count))).decode('latin1')
            result = (text.encode('latin1') if wide else text.encode('utf-16le')) + (b'\x00' if wide else b'\x00\x00') if count == 4294967295 else text.encode('latin1') if wide else text.encode('utf-16le')
            value = len(result) if wide else len(result) // 2
            if dst and cap:
                cpu.mem_write(dst, result[:cap if wide else cap * 2])
            pop = 32 if wide else 24
        elif name in ['lstrlenA', 'lstrlenW']:
            value = len(astr(args[0])) if name == 'lstrlenA' else len(wstr(args[0]))
            pop = 4
        elif name == 'CreateFileW':
            handle += 1
            value = handle
            pop = 28
            event.update(path=wstr(args[0]), access=hex(args[1]), share=args[2], security=args[3], creation=args[4], flags=hex(args[5]), template=args[6], returned_handle=value)
        elif name == 'DeviceIoControl':
            h, code, inp, ni, out, no, returned, overlapped = args[:8]
            pop = 32
            event.update(handle=h, ioctl=hex(code), input_bytes=bytes(cpu.mem_read(inp, ni)).hex() if inp else None, input_length=ni, output_length=no, overlapped=overlapped)
            if code == 2954240:
                d = descriptor()
                cpu.mem_write(out, d)
                put(returned, len(d))
                event['synthetic_descriptor'] = d.hex()
            elif code == 315412:
                s = bytes(cpu.mem_read(inp, 44))
                length = get(inp + 12)
                buf = get(inp + 20)
                cdb = s[28:28 + s[6]]
                event.update(spt_length=int.from_bytes(s[:2], 'little'), path=s[3], target=s[4], lun=s[5], cdb_len=s[6], sense_len=s[7], direction=s[8], transfer_length=length, timeout_s=get(inp + 16), sense_offset=get(inp + 24), cdb_hex=cdb.hex())
                if cdb[0] == 241:
                    io_calls += 1
                    event['request_index'] = io_calls
                    if io_calls <= failures:
                        value = 0
                    else:
                        ident = bytes(cpu.mem_read(5714640, 16))
                        version = get(5714656) & 65535
                        version -= 1 if kind == 'expected_upgrade' else 0
                        response = ident + struct.pack('<HH', version, 0)
                        cpu.mem_write(buf, response)
                        event['synthetic_f1_response'] = response.hex()
                elif cdb[0] == 240 and kind == 'expected_upgrade':
                    data = bytes(cpu.mem_read(buf, length))
                    event.update(write_index=len(writes), payload_offset=sum(map(len, writes)), data_sha256=hashlib.sha256(data).hexdigest())
                    writes.append(data)
                elif cdb[0] == 242 and kind == 'expected_upgrade':
                    f2_count += 1
                    cpu.mem_write(buf, bytes(20))
                    event.update(status_index=f2_count, status=0)
                else:
                    raise RuntimeError('Unexpected vendor opcode or write outside synthetic upgrade scenario')
                put(returned, 80 if value else 0)
            else:
                raise RuntimeError(f'Unexpected IOCTL {code:x}')
            event['return'] = value
        elif name == 'CloseHandle':
            close_calls += 1
            pop = 4
            event['handle'] = args[0]
        elif name == 'GetLastError':
            value = 121
        elif name == 'Sleep':
            pop = 4
            event.update(milliseconds=args[0], discovery_flag=bytes(cpu.mem_read(obj + 188, 1)).hex())
            if phase == 'handler' and args[0] == 300:
                pending_deadline = clock + 300
                ret(sp, pop, value)
                events.append(event)
                cpu.emu_stop()
                return
            clock += args[0]
            if phase in ['discovery', 'worker_during_quiesce'] and args[0] == 200:
                stop_reason = 'one_discovery_iteration'
                ret(sp, pop, value)
                events.append(event)
                cpu.emu_stop()
                return
        elif name == 'vswprintf_s':
            dst, cap, fmt, va = args[:4]
            fmt = wstr(fmt)
            arg = get(va)
            text = fmt.replace('%c', chr(arg & 65535)).replace('%i', str(arg))
            cpu.mem_write(dst, (text + '\x00').encode('utf-16le'))
            value = len(text)
            event.update(format=fmt, text=text)
        elif name in ['strcpy_s', 'strcat_s']:
            dst, cap, src = args[:3]
            b = (astr(dst) if name == 'strcat_s' else b'') + astr(src)
            require(len(b) + 1 <= cap, 'Context invariant failed: len(b) + 1 <= cap')
            cpu.mem_write(dst, b + b'\x00')
            value = 0
        elif name == 'memcpy':
            dst, src, count = args[:3]
            cpu.mem_write(dst, bytes(cpu.mem_read(src, count)))
            value = dst
        elif name == 'HeapAlloc':
            value = alloc(args[2])
            pop = 12
        elif name == 'HeapReAlloc':
            value = alloc(args[3], args[2])
            pop = 16
        elif name == 'HeapFree':
            pop = 12
        elif name == 'GetProcessHeap':
            value = 1
        else:
            raise RuntimeError(f'Unimplemented import {name} from {module} atreturn{get(sp):x}')
        events.append(event)
        ret(sp, pop, value)
    u.hook_add(UC_HOOK_CODE, hook)

    def start(a):
        try:
            u.emu_start(a, 50397169, count=2000000)
        except Exception:
            (R / 'last-failure.json').write_text(json.dumps({'eip': hex(u.reg_read(UC_X86_REG_EIP)), 'esp': hex(u.reg_read(UC_X86_REG_ESP)), 'recent': recent, 'events': events}, indent=2))
            raise

    def invoke(a, argument=False):
        nonlocal phase, clock, pending_deadline, worker_context, worker_fs
        sp = 16908288 if argument else 16973824
        put(sp, 50397168)
        if argument:
            put(sp + 4, obj)
        u.reg_write(UC_X86_REG_ESP, sp)
        u.reg_write(UC_X86_REG_ECX, obj)
        u.reg_write(UC_X86_REG_EBP, 0)
        put(0, 0)
        start(a)
        if argument:
            worker_context = u.context_save()
            worker_fs = get(0)
        while pending_deadline is not None:
            deadline = pending_deadline
            pending_deadline = None
            handler = u.context_save()
            handler_fs = get(0)
            phase = 'worker_during_quiesce'
            u.context_restore(worker_context)
            put(0, worker_fs)
            while clock < deadline:
                start(u.reg_read(UC_X86_REG_EIP))
            worker_context = u.context_save()
            worker_fs = get(0)
            phase = 'handler'
            clock = deadline
            u.context_restore(handler)
            put(0, handler_fs)
            start(u.reg_read(UC_X86_REG_EIP))
    invoke(4205168, True)
    selected = get(6264924)
    discovery_events = len(events)
    if selected != 255:
        phase = 'handler'
        invoke(4203728)
    return {'descriptor_case': kind, 'f1_io_failures_before_success': failures, 'selected_drive_index': selected, 'reached_handler': selected != 255, 'discovery_event_count': discovery_events, 'ioctl_f1_attempts': io_calls, 'close_calls': close_calls, 'final_discovery_flag': bytes(u.mem_read(obj + 188, 1)).hex(), 'virtual_time_ms': clock, 'stop_reason': stop_reason, 'instruction_count': instructions, 'UI_boundaries': {hex(k): v for k, v in UI.items()}, 'write_count': len(writes), 'streamed_length': sum(map(len, writes)), 'streamed_sha256': hashlib.sha256(b''.join(writes)).hexdigest(), 'f2_count': f2_count, 'ui_pump_count': ui_pump_count, 'ui_update_count': ui_update_count, 'events': events}
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, default=EXE)
    parser.add_argument('--dll', type=Path, default=DLL)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--case', choices=['expected', 'expected_upgrade', 'ascii_guli', 'raw_utf16_guli', 'non_usb'], default='expected')
    parser.add_argument('--failures', type=int, choices=range(11), default=0)
    args = parser.parse_args()
    result = emulate(args.case, args.failures, exe=args.exe, dll=args.dll, output=args.output)
    (args.output / f'trace-{args.case}-failures{args.failures}.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != 'events'}, indent=2))
