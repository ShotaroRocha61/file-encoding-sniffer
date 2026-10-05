# File Encoding Sniffer

Reads the BOM and first 4 KB of a file to guess whether it is UTF-8, UTF-16, or Latin-1. Returns one of `UTF-8-SIG`, `UTF-16`, `UTF-16LE`, `UTF-16BE`, `LATIN-1`, or `UNKNOWN`, plus a confidence level (`bom`, `bytes`, or `none`).

```python
from file_encoding_sniffer import EncodingSniffer, SniffResult

sniffer = EncodingSniffer()
result = sniffer.sniff_bytes(b"\xef\xbb\xbfhello")
print(result.encoding, result.confidence, result.has_bom)
# UTF-8-SIG bom True
```

## Why this exists

The problem is selecting a codec for legacy files of unknown provenance without pulling in a heavy dependency. The trade-off is precision: only three encodings are considered, and UTF-16-without-BOM is fundamentally ambiguous. The `confidence` field exists so callers can treat a BOM-backed answer as authoritative while treating a bytes-only answer as a best-effort guess that may need user confirmation.

## The awkward edge

ASCII text without a BOM is a trap: paired ASCII bytes form valid UTF-16 code units, so a naive decoder will happily call `"Hello, world!"` UTF-16LE. The library rejects UTF-16 without a BOM unless the decoded sample is at least 60% printable, which keeps ASCII files classified as UTF-8 but means a genuinely UTF-16 file whose first 4 KB is mostly whitespace or control characters may be misidentified. If you control the source, always write a BOM.

The returned `UTF-8-SIG` (rather than `UTF-8`) when a BOM is present is deliberate: Python's `open(path, encoding="UTF-8-SIG")` strips the BOM on read, while `encoding="UTF-8"` leaves it in the decoded string as `\ufeff`.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

