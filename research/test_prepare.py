"""Embedded-resource selection must stay unambiguous before hash validation."""
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import prepare


def resource(name, item_id, offsets):
    languages = []
    for offset in offsets:
        entry = SimpleNamespace(OffsetToData=offset, Size=8_704)
        languages.append(SimpleNamespace(data=SimpleNamespace(struct=entry)))
    item = SimpleNamespace(id=item_id, directory=SimpleNamespace(entries=languages))
    return SimpleNamespace(name=name, directory=SimpleNamespace(entries=[item]))


class EmbeddedDllTests(unittest.TestCase):
    def test_only_named_dll_resource_and_expected_id_are_hash_checked(self):
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_RESOURCE.entries = [
            resource("OTHER", 0x82, [100]),
            resource("IDR_DLL", 0x81, [200]),
            resource("IDR_DLL", 0x82, [300]),
        ]
        pe.get_data.return_value = b"selected DLL"
        with patch.object(prepare, "checked", return_value=b"checked DLL") as checked:
            self.assertEqual(prepare.extract_device_usb(pe), b"checked DLL")
        pe.get_data.assert_called_once_with(300, 8_704)
        checked.assert_called_once_with(b"selected DLL", 8_704, prepare.DLL_SHA)

    def test_missing_or_multiple_languages_are_rejected_before_hash_validation(self):
        for offsets in [[], [100, 200]]:
            with self.subTest(offsets=offsets):
                pe = MagicMock()
                pe.DIRECTORY_ENTRY_RESOURCE.entries = [resource("IDR_DLL", 0x82, offsets)]
                with patch.object(prepare, "checked") as checked:
                    with self.assertRaisesRegex(ValueError, "ambiguous embedded DeviceUsb.dll"):
                        prepare.extract_device_usb(pe)
                checked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
