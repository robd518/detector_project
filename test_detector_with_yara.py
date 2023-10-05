import unittest
from detector_with_yara import YaraScanner

class TestBadDirectories(unittest.TestCase):
    def setUp(self):
        fake_directory = '/some/bad/and/also/fake/directory/'
        self.scanner = YaraScanner(fake_directory, fake_directory)

    def test_non_existent_rules_directory(self):
        self.assertRaises(FileNotFoundError, self.scanner.compile_rules)

    def test_non_existent_files_directory(self):
        self.assertRaises(FileNotFoundError, self.scanner.run)

if __name__ == "__main__":
    unittest.main()
