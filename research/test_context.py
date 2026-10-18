"""Run with Python -O: expanded reference and control-flow checks stay active."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from run_context_suite import validate_result

import emulate_context as emulator


class ContextGuardTests(unittest.TestCase):
    def test_windows_text_conversion_preserves_explicit_and_terminated_lengths(self):
        for wide_input in [False, True]:
            source_encoding = "utf-16le" if wide_input else "latin1"
            target_encoding = "latin1" if wide_input else "utf-16le"
            source_terminator = b"\x00\x00" if wide_input else b"\x00"
            target_terminator = b"\x00" if wide_input else b"\x00\x00"
            text = "caf\u00e9"
            data = text.encode(source_encoding) + source_terminator + b"unread"
            for count in [len(text), 4294967295]:
                with self.subTest(wide_input=wide_input, count=count):
                    memory = MagicMock()
                    memory.mem_read.side_effect = lambda address, size: data[
                        address - 100 : address - 100 + size
                    ]
                    converted = emulator.convert_windows_text(
                        memory, 100, count, wide_input=wide_input
                    )
                    expected = text.encode(target_encoding)
                    if count == 4294967295:
                        expected += target_terminator
                    self.assertEqual(converted, expected)

    def test_windows_text_conversion_does_not_replace_unrepresentable_characters(self):
        memory = MagicMock()
        memory.mem_read.return_value = "\u0100".encode("utf-16le")
        with self.assertRaises(UnicodeEncodeError):
            emulator.convert_windows_text(memory, 100, 1, wide_input=True)

    def test_terminated_strings_read_complete_code_units_without_reading_past_end(self):
        for contents, terminator in [
            (b"", b"\x00"),
            (b"Guli\xff", b"\x00"),
            ("\u0100Z".encode("utf-16le"), b"\x00\x00"),
        ]:
            with self.subTest(contents=contents, terminator=terminator):
                data = contents + terminator
                memory = MagicMock()
                memory.mem_read.side_effect = lambda address, size: data[
                    address - 100 : address - 100 + size
                ]
                result = emulator.read_terminated_bytes(memory, 100, terminator)
                self.assertEqual(result, contents)
                self.assertIsInstance(result, bytearray)
                self.assertEqual(
                    memory.mem_read.call_args_list,
                    [
                        call(100 + offset, len(terminator))
                        for offset in range(0, len(data), len(terminator))
                    ],
                )

    def test_unreviewed_exe_is_rejected_before_dll_or_pe_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = root / "unknown.exe"
            unknown.write_bytes(b"not the reviewed executable")
            with self.assertRaisesRegex(ValueError, "reviewed executable"):
                emulator.emulate(
                    exe=unknown, dll=root / "missing.dll", output=root / "output"
                )
            self.assertFalse((root / "output").exists())

    def test_dll_is_checked_before_either_image_is_parsed(self):
        with (
            patch.object(
                emulator,
                "read_reference",
                side_effect=[b"checked EXE", ValueError("not the reviewed DLL")],
            ),
            patch.object(emulator.pefile, "PE") as parser,
        ):
            with self.assertRaisesRegex(ValueError, "reviewed DLL"):
                emulator.emulate()
            parser.assert_not_called()

    def test_divergent_selection_cannot_pass_with_python_optimization(self):
        with self.assertRaisesRegex(ValueError, "selected_drive_index"):
            validate_result({"events": [], "selected_drive_index": 255}, "expected", 0)

    def test_failure_trace_keeps_last_thirty_instruction_addresses_in_order(self):
        image = MagicMock()
        image.OPTIONAL_HEADER.ImageBase = 0x400000
        image.OPTIONAL_HEADER.SizeOfImage = 4096
        image.get_memory_mapped_image.return_value = b""
        image.DIRECTORY_ENTRY_IMPORT = []
        image.DIRECTORY_ENTRY_EXPORT.symbols = [
            SimpleNamespace(name=name.encode(), address=index * 16)
            for index, name in enumerate(
                [
                    "deviceUsb_OpenByDrv",
                    "deviceUsb_GetInfo",
                    "deviceUsb_Close",
                    "deviceUsb_Request",
                ]
            )
        ]
        engine = MagicMock()
        engine.reg_read.return_value = 0
        addresses = list(range(0x1000, 0x1028))

        def fail_after_instructions(*args, **kwargs):
            hook = engine.hook_add.call_args.args[1]
            for address in addresses:
                hook(engine, address, 1, None)
            raise RuntimeError("synthetic instruction failure")

        engine.emu_start.side_effect = fail_after_instructions
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(emulator, "read_reference", return_value=b"checked"),
                patch.object(emulator.pefile, "PE", return_value=image),
                patch.object(emulator, "Uc", return_value=engine),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "synthetic instruction failure"
                ):
                    emulator.emulate(output=directory)
            failure = json.loads((Path(directory) / "last-failure.json").read_text())
        self.assertEqual(
            failure["recent"], [hex(address) for address in addresses[-30:]]
        )
        self.assertEqual(failure["eip"], "0x0")
        self.assertEqual(failure["esp"], "0x0")
        self.assertEqual(failure["events"], [])


if __name__ == "__main__":
    unittest.main()
