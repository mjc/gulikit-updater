"""Run under python -O too: input and baseline checks must remain active."""
import tempfile
import unittest
from pathlib import Path

import emulate_update as emulator


class EmulatorContractTests(unittest.TestCase):
    def test_unreviewed_executable_is_rejected_before_parsing(self):
        previous = emulator.EXE
        self.addCleanup(setattr, emulator, "EXE", previous)
        with tempfile.TemporaryDirectory() as directory:
            emulator.EXE = Path(directory) / "unknown.exe"
            emulator.EXE.write_bytes(b"not a reviewed executable")
            with self.assertRaisesRegex(ValueError, "reviewed executable"):
                emulator.emulate()

    def test_divergent_baseline_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "baseline"):
            emulator.validate_results({"success": {"exit_va": "wrong"}})


if __name__ == "__main__":
    unittest.main()
