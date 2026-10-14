from pathlib import Path
import tempfile
import unittest

import main


class EditToolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "file.txt"

    def test_replace_and_delete_preserve_line_endings(self):
        self.path.write_bytes(b"first\r\nsecond\r\n")
        self.assertEqual(main.edit_tool(str(self.path), "second", "new"), "OK")
        self.assertEqual(self.path.read_bytes(), b"first\r\nnew\r\n")
        main.edit_tool(str(self.path), "new\r\n", "")
        self.assertEqual(self.path.read_bytes(), b"first\r\n")

    def test_create_nested_file_and_append(self):
        path = self.path.parent / "nested" / "file.txt"
        result = main.edit_tool(str(path), "", "hello")
        self.assertEqual(result, f"Successfully created file {path}")
        main.edit_tool(str(path), "", " world")
        self.assertEqual(path.read_text(), "hello world")

    def test_rejected_edits_leave_file_unchanged(self):
        self.path.write_text("repeat repeat")
        for old_str, new_str, message in [
            ("repeat", "new", "must be unique"),
            ("missing", "new", "not found"),
            ("repeat", "repeat", "invalid input"),
            ("", "", "invalid input"),
        ]:
            with self.subTest(old_str=old_str, new_str=new_str):
                with self.assertRaisesRegex(ValueError, message):
                    main.edit_tool(str(self.path), old_str, new_str)
                self.assertEqual(self.path.read_text(), "repeat repeat")

    def test_missing_file_requires_empty_old_string(self):
        with self.assertRaises(FileNotFoundError):
            main.edit_tool(str(self.path), "missing", "new")
        self.assertFalse(self.path.exists())
        with self.assertRaises(ValueError):
            main.edit_tool("", "", "new")

    def test_tool_registration_and_schema(self):
        self.assertIs(main.tool_registry[("files", "edit_tool")], main.edit_tool)
        files = next(tool for tool in main.get_tools() if tool["name"] == "files")
        edit = next(tool for tool in files["tools"] if tool["name"] == "edit_tool")
        self.assertEqual(edit["parameters"]["required"], ["path", "old_str", "new_str"])
        self.assertTrue(edit["strict"])
        self.assertFalse(edit["parameters"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
