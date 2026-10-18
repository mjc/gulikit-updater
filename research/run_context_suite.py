"""Validate seven bounded Windows-context scenarios; no host device I/O."""

import argparse
import hashlib
import json
from pathlib import Path
from emulate_context import emulate, EXE, DLL, OUTPUT
from emulate_update import require


def validate_result(x, case, failures):
    events = x["events"]
    selected = case.startswith("expected")
    require(
        x["selected_drive_index"] == (4 if selected else 255),
        "Context invariant failed: x['selected_drive_index'] == (4 if selected else 255)",
    )
    require(
        x["reached_handler"] == selected and x["close_calls"] == (2 if selected else 1),
        "Context invariant failed: x['reached_handler'] == selected and x['close_calls'] =",
    )
    require(
        x["final_discovery_flag"] == "01" and (not x["UI_boundaries"]),
        "Context invariant failed: x['final_discovery_flag'] == '01' and (not x['UI_bounda",
    )
    exports = [
        (e["phase"], e["name"]) for e in events if e["kind"] == "actual_vendor_export"
    ]
    expected = [
        ("discovery", "deviceUsb_OpenByDrv"),
        ("discovery", "deviceUsb_GetInfo"),
        ("discovery", "deviceUsb_Close"),
    ]
    if selected:
        expected += (
            [("handler", "deviceUsb_OpenByDrv")]
            + [("handler", "deviceUsb_Request")]
            * (677 if case == "expected_upgrade" else 1)
            + [("handler", "deviceUsb_Close")]
        )
    require(exports == expected, (case, exports))
    io = [e for e in events if e.get("ioctl") == "0x4d014"]
    require(
        len(io)
        == (
            677
            if case == "expected_upgrade"
            else min(failures + 1, 10)
            if selected
            else 0
        ),
        "Context invariant failed: len(io) == (677 if case == 'expected_upgrade' else min(",
    )
    for e in io:
        require(
            e["cdb_len"] == 10 and e["timeout_s"] == 5,
            "Context invariant failed: e['cdb_len'] == 10 and e['timeout_s'] == 5",
        )
    for e in io:
        if not e["cdb_hex"].startswith("f1"):
            continue
        require(
            e["cdb_hex"] == "f10000000000a5a54500"
            and e["transfer_length"] == 20
            and (e["direction"] == 1),
            "Context invariant failed: e['cdb_hex'] == 'f10000000000a5a54500' and e['transfer_",
        )
    query = [e for e in events if e.get("ioctl") == "0x2d1400"]
    require(
        len(query) == 1 and query[0]["input_bytes"] == "0000000000000000a5a5a5a5",
        "Context invariant failed: len(query) == 1 and query[0]['input_bytes'] == '0000000",
    )
    if case == "expected_upgrade":
        validate_upgrade_trace(x, events, io)
    else:
        require(
            x["write_count"] == 0 and x["f2_count"] == 0,
            "Context invariant failed: x['write_count'] == 0 and x['f2_count'] == 0",
        )
    if selected:
        require(
            x["stop_reason"] == "function_return",
            "Context invariant failed: x['stop_reason'] == 'function_return'",
        )
    validate_worker_quiescence(x, events, io, selected, failures)


def validate_upgrade_trace(x, events, io):
    require(
        x["write_count"] == 674
        and x["streamed_length"] == 345088
        and (
            x["streamed_sha256"]
            == "2e0e89d458eb39f30eaa1ba9f4038039ad95c2eeed0e392ecfb0d5ece3441826"
        ),
        "Context invariant failed: x['write_count'] == 674 and x['streamed_length'] == 345",
    )
    require(
        x["f2_count"] == 2
        and x["ui_pump_count"] == 674
        and (x["ui_update_count"] == 674),
        "Context invariant failed: x['f2_count'] == 2 and x['ui_pump_count'] == 674 and (x",
    )
    dialogs = [e["text"] for e in events if e.get("name") == "MessageBoxW"]
    require(
        dialogs
        == [
            "Do you want to upgrade from ver:5.06 to ver:5.07?\n",
            "Upgrade success!\n",
        ],
        "Context invariant failed: dialogs == ['Do you want to upgrade from ver:5.06 to ve",
    )
    opcodes = [e["cdb_hex"][:2] for e in io]
    require(
        opcodes[:3] == ["f1", "f0", "f2"]
        and opcodes[-1] == "f2"
        and (opcodes.count("f0") == 674),
        "Context invariant failed: opcodes[:3] == ['f1', 'f0', 'f2'] and opcodes[-1] == 'f",
    )
    write_index = 0
    payload_offset = 0
    for e in io:
        if e["cdb_hex"].startswith("f0"):
            require(
                e["direction"] == 0 and e["transfer_length"] == 512,
                "Context invariant failed: e['direction'] == 0 and e['transfer_length'] == 512",
            )
            require(
                e["write_index"] == write_index
                and e["payload_offset"] == payload_offset,
                "Context invariant failed: firmware write index or payload offset diverged",
            )
            write_index += 1
            payload_offset += e["transfer_length"]
        elif e["cdb_hex"].startswith("f2"):
            require(
                e["direction"] == 1 and e["transfer_length"] == 20,
                "Context invariant failed: e['direction'] == 1 and e['transfer_length'] == 20",
            )


def validate_worker_quiescence(x, events, io, selected, failures):
    worker = [e for e in events if e.get("phase") == "worker_during_quiesce"]
    require(
        not any(
            (
                e["kind"] == "actual_vendor_export"
                or e.get("name") == "GetLogicalDrives"
                for e in worker
            )
        ),
        "Context invariant failed: not any((e['kind'] == 'actual_vendor_export' or e.get('",
    )
    sleeps = [e for e in events if e.get("name") == "Sleep"]
    retry_sleeps = sum(e["milliseconds"] == 20 for e in sleeps)
    require(
        retry_sleeps == (min(failures, 9) if selected else 0),
        "Context invariant failed: len([e for e in sleeps if e['milliseconds'] == 20]) == ",
    )
    if selected:
        require(
            len(worker) == 2
            and all(
                (
                    e.get("milliseconds") == 200 and e["discovery_flag"] == "00"
                    for e in worker
                )
            ),
            "Context invariant failed: len(worker) == 2 and all((e.get('milliseconds') == 200 ",
        )
        require(
            any(
                (
                    e["milliseconds"] == 300 and e["discovery_flag"] == "00"
                    for e in sleeps
                )
            ),
            "Context invariant failed: any((e['milliseconds'] == 300 and e['discovery_flag'] =",
        )
        require(
            io[0]["virtual_time_ms"] == 500,
            "Context invariant failed: io[0]['virtual_time_ms'] == 500",
        )
        require(
            x["virtual_time_ms"] == 500 + 20 * min(failures, 9),
            "Context invariant failed: x['virtual_time_ms'] == 500 + 20 * min(failures, 9)",
        )
    else:
        require(
            x["virtual_time_ms"] == 200,
            "Context invariant failed: x['virtual_time_ms'] == 200",
        )


def run_suite(exe=EXE, dll=DLL, output=OUTPUT):
    output = Path(output)
    summary = []
    for case, failures in [
        ("expected", 0),
        ("expected", 2),
        ("expected", 10),
        ("ascii_guli", 0),
        ("raw_utf16_guli", 0),
        ("non_usb", 0),
        ("expected_upgrade", 0),
    ]:
        result = emulate(case, failures, exe=exe, dll=dll, output=output)
        validate_result(result, case, failures)
        (output / f"trace-{case}-failures{failures}.json").write_text(
            json.dumps(result, indent=2)
        )
        summary.append({k: v for k, v in result.items() if k != "events"})
    result = {
        "all_passed": True,
        "scenario_count": len(summary),
        "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "dll_sha256": hashlib.sha256(dll.read_bytes()).hexdigest(),
        "scenarios": summary,
    }
    (output / "suite-summary.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=EXE)
    parser.add_argument("--dll", type=Path, default=DLL)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    result = run_suite(args.exe, args.dll, args.output)
    print(
        f"{result['scenario_count']} context scenarios passed, including the complete synthetic update; no device access"
    )
