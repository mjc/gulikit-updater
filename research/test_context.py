"""Run with Python -O: expanded reference and control-flow checks stay active."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run_context_suite import validate_result

import emulate_context as emulator


class ContextGuardTests(unittest.TestCase):
    def test_unreviewed_exe_is_rejected_before_dll_or_pe_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = root / "unknown.exe"
            unknown.write_bytes(b"not the reviewed executable")
            with self.assertRaisesRegex(ValueError, "reviewed executable"):
                emulator.emulate(exe=unknown, dll=root / "missing.dll", output=root / "output")
            self.assertFalse((root / "output").exists())


    def test_dll_is_checked_before_either_image_is_parsed(self):
        with patch.object(emulator, "read_reference", side_effect=[b"checked EXE", ValueError("not the reviewed DLL")]), patch.object(emulator.pefile, "PE") as parser:
            with self.assertRaisesRegex(ValueError, "reviewed DLL"):
                emulator.emulate()
            parser.assert_not_called()

    def test_divergent_selection_cannot_pass_with_python_optimization(self):
        with self.assertRaisesRegex(ValueError, "selected_drive_index"):
            validate_result({"events": [], "selected_drive_index": 255}, "expected", 0)


if __name__ == "__main__":
    unittest.main()
