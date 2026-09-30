from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SniffResult:
    """The outcome of an encoding sniff.

    Attributes:
        encoding: One of ``'UTF-8-SIG'``, ``'UTF-16'``, ``'UTF-16LE'``,
            ``'UTF-16BE'``, ``'LATIN-1'``, or ``'UNKNOWN'``. The ``'UTF-8-SIG'``
            spelling (used by Python's :mod:`codecs` module) signals to callers
            that the BOM should be stripped on open.
        confidence: ``'bom'`` when the decision was driven purely by a byte order
            mark, ``'bytes'`` when it was inferred from decoding the first 4 KB of
            content, or ``'none'`` when no conclusion could be reached.
        has_bom: True when a BOM was actually found. Distinguishes a UTF-8 file
            that happens to start with U+FEFF from one that does not.
    """

    encoding: str
    confidence: str
    has_bom: bool


class EncodingSniffer:
    """Guess a text file's encoding by inspecting its BOM and leading bytes.

    Only the three encodings named in the project brief are considered:
    UTF-16 (little- or big-endian), and Latin-1. A file is never
    reported as any other encoding.

    Detection proceeds in two phases:

    1. **BOM.** The first four bytes are compared against the BOM signatures
       for UTF-8, UTF-16LE, and UTF-16BE. A match is authoritative — the
       returned ``encoding`` will be the Python codec name that, when passed to
       ``open(..., encoding=...)``, causes the BOM to be consumed correctly.
    2. **Bytes.** Without a BOM, the first 4 KB of the file are decoded as
       each candidate in turn, preferring UTF-8 first (as the modern default)
       then Latin-1 (which never fails, since it maps every byte value).
       UTF-16 is tried only as a last resort and only when the content looks
       like plausible text — a plain ASCII file would otherwise be
       misidentified as UTF-16LE, because ASCII bytes happen to form valid
       UTF-16 code units when paired.

    The ``confidence`` field tells the caller which phase produced the answer,
    so they can decide whether to trust it for binary-versus-text decisions
    or only for codec selection.
    """

    UTF8_BOM = b"\xef\xbb\xbf"
    UTF16_LE_BOM = b"\xff\xfe"
    UTF16_BE_BOM = b"\xfe\xff"
    SAMPLE_SIZE = 4096

    def sniff_bytes(self, data: bytes) -> SniffResult:
        """Inspect an in-memory byte buffer and return a :class:`SniffResult`.

        Only the prefix matters; the caller may truncate the buffer to
        ``SAMPLE_SIZE`` bytes before calling to reduce work.
        """
        return self._detect(data)

    def sniff_file(self, path: str | os.PathLike[str]) -> SniffResult:
        """Open ``path`` in binary mode, read a sample, and return a guess."""
        with open(path, "rb") as fh:
            data = fh.read(self.SAMPLE_SIZE)
        return self._detect(data)

    def _detect(self, data: bytes) -> SniffResult:
        bom_result = self._check_bom(data)
        if bom_result is not None:
            return bom_result
        return self._infer_from_bytes(data)

    def _check_bom(self, data: bytes) -> SniffResult | None:
        # UTF-8 BOM is three bytes; the UTF-16 BOMs are two. We must test the
        # three-byte UTF-8 marker first, otherwise a UTF-8 file whose second
        # byte happens to be 0xBB 0xBF could be mistaken for UTF-16. In
        # practice that overlap is impossible (the UTF-8 BOM's first byte is
        # 0xEF, neither UTF-16 marker), but the ordering keeps the rule
        # explicit and robust to future signature additions.
        if data.startswith(self.UTF8_BOM):
            return SniffResult("UTF-8-SIG", "bom", True)
        if data.startswith(self.UTF16_LE_BOM):
            return SniffResult("UTF-16LE", "bom", True)
        if data.startswith(self.UTF16_BE_BOM):
            return SniffResult("UTF-16BE", "bom", True)
        return None

    def _infer_from_bytes(self, data: bytes) -> SniffResult:
        # UTF-8 is the modern default and must be tried before Latin-1, which
        # would otherwise accept every byte sequence and mask a genuine UTF-8
        # file that simply lacks a BOM.
        if self._decodes_clean(data, "utf-8"):
            return SniffResult("UTF-8", "bytes", False)

        # UTF-16 without a BOM is genuinely ambiguous. A naive decoder would
        # happily read pure ASCII as UTF-16LE, because pairs of ASCII bytes
        # are valid UTF-16 code units in the Basic Latin block. To avoid that
        # trap we require the decode to succeed *and* the result to contain a
        # reasonable proportion of printable text.
        for enc in ("utf-16-le", "utf-16-be"):
            if self._looks_like_utf16(data, enc):
                # Normalise to the endian-neutral Python codec name; the
                # absence of a BOM means the caller must keep handling
                # endianness themselves, which "UTF-16" signals.
                return SniffResult("UTF-16", "bytes", False)

        # Latin-1 maps every byte value 0-255 to a character, so this decode
        # cannot raise. It is the safe fallback for legacy text.
        return SniffResult("LATIN-1", "bytes", False)

    @staticmethod
    def _decodes_clean(data: bytes, encoding: str) -> bool:
        try:
            data.decode(encoding)
        except UnicodeDecodeError:
            return False
        return True

    def _looks_like_utf16(self, data: bytes, encoding: str) -> bool:
        if len(data) < 2 or len(data) % 2 != 0:
            return False
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            return False
        if not text:
            return True
        printable = sum(1 for ch in text if ch == "\n" or ch == "\r" or not ch.isspace() and ch.isprintable())
        # 0.6 is a deliberately permissive floor: UTF-16 text often contains
        # CJK or combining marks that str.isprintable() still counts, so real
        # text lands well above it, while random bytes rarely do.
        if printable / len(text) < 0.6:
            return False
        # A BOM-less UTF-16 file of ASCII-range text contains many NUL bytes
        # (the high byte of each code unit is zero). Require at least one NUL
        # so that a short Latin-1 buffer that happens to decode into CJK
        # characters is not mistaken for UTF-16.
        return b"\x00" in data
