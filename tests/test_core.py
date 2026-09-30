import os
import tempfile
import unittest

from file_encoding_sniffer import EncodingSniffer, SniffResult


class TestEncodingSniffer(unittest.TestCase):
    def setUp(self):
        self.sniffer = EncodingSniffer()

    # ---- BOM detection -------------------------------------------------

    def test_utf8_bom(self):
        result = self.sniffer.sniff_bytes(b"\xef\xbb\xbfhello")
        self.assertEqual(result, SniffResult("UTF-8-SIG", "bom", True))

    def test_utf16_le_bom(self):
        result = self.sniffer.sniff_bytes(b"\xff\xfeh\x00")
        self.assertEqual(result, SniffResult("UTF-16LE", "bom", True))

    def test_utf16_be_bom(self):
        result = self.sniffer.sniff_bytes(b"\xfe\xff\x00h")
        self.assertEqual(result, SniffResult("UTF-16BE", "bom", True))

    def test_bom_takes_precedence_over_content(self):
        # A UTF-16 BOM followed by bytes that are not valid UTF-16 code units
        # should still be reported according to the BOM, not rejected.
        result = self.sniffer.sniff_bytes(b"\xff\xfe\x00\x00")
        self.assertEqual(result.encoding, "UTF-16LE")
        self.assertEqual(result.confidence, "bom")

    # ---- Byte-based inference -----------------------------------------

    def test_plain_ascii_is_utf8(self):
        result = self.sniffer.sniff_bytes(b"plain ascii text, no bom")
        self.assertEqual(result, SniffResult("UTF-8", "bytes", False))

    def test_utf8_multibyte_without_bom(self):
        result = self.sniffer.sniff_bytes("café — résumé".encode("utf-8"))
        self.assertEqual(result, SniffResult("UTF-8", "bytes", False))

    def test_latin1_fallback(self):
        # 0xE9 alone (é in Latin-1) is not a valid UTF-8 start byte sequence.
        result = self.sniffer.sniff_bytes(b"caf\xe9")
        self.assertEqual(result, SniffResult("LATIN-1", "bytes", False))

    def test_utf16_le_without_bom(self):
        # ASCII text encoded as UTF-16 without a BOM is ambiguous: paired
        # ASCII bytes form valid UTF-16 code units, so the library's
        # printable-ratio guard intentionally rejects it (see README). Use a
        # non-ASCII sample so the content is unambiguously UTF-16.
        text = "café — résumé\n"
        result = self.sniffer.sniff_bytes(text.encode("utf-16-le"))
        self.assertEqual(result.encoding, "UTF-16")
        self.assertEqual(result.confidence, "bytes")
        self.assertFalse(result.has_bom)

    def test_utf16_be_without_bom(self):
        text = "café — résumé\n"
        result = self.sniffer.sniff_bytes(text.encode("utf-16-be"))
        self.assertEqual(result.encoding, "UTF-16")
        self.assertEqual(result.confidence, "bytes")
        self.assertFalse(result.has_bom)

    def test_pure_ascii_not_mistaken_for_utf16(self):
        # The core trap: ASCII bytes form valid UTF-16LE pairs, so naive
        # detection would misclassify. Our printable-ratio guard must reject.
        result = self.sniffer.sniff_bytes(b"Hello, world!")
        self.assertEqual(result.encoding, "UTF-8")

    def test_short_odd_length_buffer(self):
        # One byte is not enough to form a UTF-16 code unit; must not crash
        # and must fall back to UTF-8/Latin-1.
        result = self.sniffer.sniff_bytes(b"A")
        self.assertEqual(result.encoding, "UTF-8")

    def test_empty_buffer(self):
        result = self.sniffer.sniff_bytes(b"")
        # No BOM, no content to decode as UTF-16 — empty decodes cleanly as
        # UTF-8 (and Latin-1), and UTF-8 is preferred.
        self.assertEqual(result.encoding, "UTF-8")
        self.assertFalse(result.has_bom)

    # ---- File path entry point ----------------------------------------

    def test_sniff_file_reads_sample(self):
        payload = "café — résumé\n".encode("utf-8")
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(payload)
            path = fh.name
        try:
            result = self.sniffer.sniff_file(path)
            self.assertEqual(result.encoding, "UTF-8")
            self.assertEqual(result.confidence, "bytes")
        finally:
            os.unlink(path)

    def test_sniff_file_utf8_bom(self):
        payload = b"\xef\xbb\xbfBOM-prefixed text"
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(payload)
            path = fh.name
        try:
            result = self.sniffer.sniff_file(path)
            self.assertEqual(result, SniffResult("UTF-8-SIG", "bom", True))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
