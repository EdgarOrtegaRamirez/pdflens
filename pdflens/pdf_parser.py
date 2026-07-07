"""
Low-level PDF parser — reads binary PDF structure including objects,
cross-reference tables, and trailers without external dependencies.

Implements a hand-written recursive descent parser for the PDF object format.
"""

from __future__ import annotations

import contextlib
import re
import zlib
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any


class ObjectType(Enum):
    BOOLEAN = auto()
    NUMBER = auto()
    STRING_LITERAL = auto()
    STRING_HEX = auto()
    NAME = auto()
    ARRAY = auto()
    DICTIONARY = auto()
    STREAM = auto()
    REF = auto()
    NULL = auto()


@dataclass
class PDFObject:
    """Represents a parsed PDF object."""

    type: ObjectType
    value: Any = None
    obj_num: int | None = None
    gen_num: int = 0
    offset: int = 0
    # For streams
    stream_data: bytes | None = None
    stream_dict: dict | None = None

    def as_dict(self) -> dict:
        if self.type == ObjectType.DICTIONARY and isinstance(self.value, dict):
            return self.value
        return {}

    def get(self, key: str, default=None):
        d = self.as_dict()
        return d.get(key, default)

    def resolve(self, xref: dict) -> PDFObject:
        """Resolve a reference to its target object."""
        if self.type == ObjectType.REF and isinstance(self.value, tuple):
            ref_num, ref_gen = self.value
            return xref.get(ref_num, self)
        return self


@dataclass
class XRefEntry:
    """A single cross-reference entry."""

    obj_num: int
    gen_num: int
    offset: int  # byte offset of object in file
    free: bool = False
    in_use: bool = True


@dataclass
class XRefTable:
    """Complete cross-reference table."""

    entries: dict[int, XRefEntry] = field(default_factory=dict)
    startxref: int = 0
    prev_xref: int | None = None

    def get_offset(self, obj_num: int) -> int | None:
        entry = self.entries.get(obj_num)
        if entry and entry.in_use:
            return entry.offset
        return None


@dataclass
class ParsedPDF:
    """Result of parsing a PDF file."""

    header_version: str = ""
    trailer: dict = field(default_factory=dict)
    xref: XRefTable = field(default_factory=XRefTable)
    objects: dict[int, PDFObject] = field(default_factory=dict)
    streams: list[tuple[int, bytes]] = field(default_factory=list)
    raw_bytes: bytes = b""
    file_size: int = 0


class PDFParseError(Exception):
    """Raised when PDF parsing fails."""


class PDFParser:
    """
    Hand-written PDF parser that reads the binary structure.

    Supports:
    - PDF versions 1.0 through 2.0
    - All standard object types
    - Cross-reference tables and streams
    - Stream decompression (FlateDecode)
    - Linearized PDF detection
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.length = len(data)
        self.objects: dict[int, PDFObject] = {}
        self.xref = XRefTable()
        self.trailer: dict = {}
        self.header_version = ""
        self.streams: list[tuple[int, bytes]] = []

    def parse(self) -> ParsedPDF:
        """Parse the entire PDF file."""
        self._parse_header()
        self._find_xref()
        self._parse_xref_table()
        self._parse_trailer()
        self._parse_all_objects()

        return ParsedPDF(
            header_version=self.header_version,
            trailer=self.trailer,
            xref=self.xref,
            objects=self.objects,
            streams=self.streams,
            raw_bytes=self.data,
            file_size=len(self.data),
        )

    def _parse_header(self):
        """Parse the PDF header (e.g., %PDF-1.7)."""
        self.pos = 0
        header_line = self._read_line()
        match = re.match(rb"%PDF-(\d+\.\d+)", header_line)
        if not match:
            raise PDFParseError(f"Invalid PDF header: {header_line!r}")
        self.header_version = match.group(1).decode("ascii")
        # Skip header comment and binary marker
        self.pos = self.data.find(b"\n", self.pos)
        if self.pos == -1:
            self.pos = self.length
        else:
            self.pos += 1

    def _find_xref(self):
        """Find the startxref value pointing to the xref table."""
        # Search backwards for 'startxref'
        if self.length > 1024:
            search_start = self.length - 1024
            idx = self.data.rfind(b"startxref", search_start)
        else:
            idx = self.data.rfind(b"startxref")
        if idx == -1:
            raise PDFParseError("No startxref found")
        # Find the offset after 'startxref'
        after = self.data[idx + 9 :]
        # Skip whitespace
        after = after.lstrip(b"\n\r ")
        # Read the number
        num_match = re.match(rb"(\d+)", after)
        if not num_match:
            raise PDFParseError("Invalid startxref value")
        self.xref.startxref = int(num_match.group(1))

    def _parse_xref_table(self):
        """Parse the cross-reference table."""
        self.pos = self.xref.startxref
        self._skip_whitespace()

        token = self._read_token()
        if token == b"xref":
            self._parse_xref_subsections()
        elif token == b"obj":
            # Cross-reference stream (PDF 1.5+) — startxref points directly at 'obj' keyword
            self._parse_xref_stream()
        elif token is not None and token.isdigit():
            # startxref points to an object header like "4 0 obj" — xref stream
            self._parse_xref_stream()
        else:
            raise PDFParseError(f"Expected 'xref' or object, got {token!r}")

    def _parse_xref_subsections(self):
        """Parse xref subsections."""
        while self.pos < self.length:
            self._skip_whitespace()
            token = self._peek_token()
            if token is None or token in (b"trailer", b"startxref", b"%%EOF"):
                break
            # Check if it's a subsection header: "first_obj count"
            try:
                first_num = int(token)
            except (ValueError, TypeError):
                break
            self._skip_token()
            count = int(self._read_token())
            self._skip_whitespace()
            for i in range(first_num, first_num + count):
                entry_line = self._read_line().strip()
                parts = entry_line.split()
                if len(parts) >= 3:
                    offset = int(parts[0])
                    gen = int(parts[1])
                    in_use = parts[2] == b"n"
                    self.xref.entries[i] = XRefEntry(
                        obj_num=i, gen_num=gen, offset=offset, free=not in_use, in_use=in_use
                    )

    def _parse_xref_stream(self):
        """Parse a cross-reference stream (PDF 1.5+)."""
        # Reposition to the start of the xref stream object
        self.pos = self.xref.startxref
        obj = self._parse_object_body()
        if obj is not None and obj.type == ObjectType.STREAM:
            # Stream objects store their dictionary in stream_dict or value
            stream_dict = {}
            if isinstance(obj.value, dict):
                stream_dict = obj.value
            elif isinstance(obj.stream_dict, dict):
                stream_dict = obj.stream_dict

            def _get_val(key, default=None):
                v = stream_dict.get(key)
                if v is None:
                    return default
                return v.value if hasattr(v, "value") else v

            # The xref stream contains /W array describing field widths
            w_obj = _get_val(b"/W", [])
            _get_val(b"/Size", 0)
            root = _get_val(b"/Root")
            info = _get_val(b"/Info")
            prev = _get_val(b"/Prev")
            if root is not None:
                self.trailer[b"/Root"] = root
            if info is not None:
                self.trailer[b"/Info"] = info
            if prev is not None:
                self.xref.prev_xref = prev if isinstance(prev, int) else None

            # Parse the W array to get field widths
            if isinstance(w_obj, list):
                w = []
                for item in w_obj:
                    w.append(item.value if hasattr(item, "value") else item)
            elif isinstance(w_obj, PDFObject) and w_obj.type == ObjectType.ARRAY:
                w = []
                for item in w_obj.value:
                    w.append(item.value if hasattr(item, "value") else item)
            else:
                w = []

            # If we have stream data, try to decode xref entries
            if obj.stream_data and isinstance(w, list) and len(w) == 3:
                w0, w1, w2 = [int(x) for x in w]
                decoded = obj.stream_data
                # Try FlateDecode
                with contextlib.suppress(Exception):
                    decoded = zlib.decompress(decoded)
                # Parse entries
                entry_size = w0 + w1 + w2
                if entry_size > 0:
                    num_entries = len(decoded) // entry_size
                    obj_num = 0
                    for i in range(num_entries):
                        chunk = decoded[i * entry_size : (i + 1) * entry_size]
                        f0 = int.from_bytes(chunk[:w0], "big") if w0 > 0 else 0
                        f1 = int.from_bytes(chunk[w0 : w0 + w1], "big") if w1 > 0 else 0
                        f2 = int.from_bytes(chunk[w0 + w1 :], "big") if w2 > 0 else 0

                        if f0 == 0:  # type 0: free
                            self.xref.entries[obj_num] = XRefEntry(
                                obj_num=obj_num, gen_num=f2, offset=0, free=True, in_use=False
                            )
                        elif f0 == 1:  # type 1: uncompressed
                            self.xref.entries[obj_num] = XRefEntry(obj_num=obj_num, gen_num=f2, offset=f1, in_use=True)
                        elif f0 == 2:  # type 2: compressed in stream
                            self.xref.entries[obj_num] = XRefEntry(obj_num=obj_num, gen_num=0, offset=f1, in_use=True)
                        obj_num += 1

    def _parse_trailer(self):
        """Parse the trailer dictionary."""
        # Find 'trailer' keyword
        idx = self.data.find(b"trailer", self.pos)
        if idx == -1:
            return
        self.pos = idx + 7
        self._skip_whitespace()
        obj = self._parse_value()
        if obj and obj.type == ObjectType.DICTIONARY:
            self.trailer = obj.value if isinstance(obj.value, dict) else {}

    def _parse_all_objects(self):
        """Parse all objects referenced in the xref table."""
        for obj_num, entry in self.xref.entries.items():
            if entry.in_use and entry.offset > 0 and entry.offset < self.length:
                self.pos = entry.offset
                self._skip_whitespace()
                token = self._peek_token()
                if token and re.match(rb"\d+", token):
                    obj = self._parse_object_body()
                    if obj is not None:
                        obj.obj_num = obj_num
                        obj.gen_num = entry.gen_num
                        obj.offset = entry.offset
                        self.objects[obj_num] = obj
                        if obj.type == ObjectType.STREAM and obj.stream_data:
                            self.streams.append((obj_num, obj.stream_data))

    def _parse_object_body(self) -> PDFObject | None:
        """Parse a full object: obj_num gen_num obj ... endobj."""
        try:
            obj_num_token = self._read_token()
            if obj_num_token is None:
                return None
            obj_num = int(obj_num_token)
        except (ValueError, TypeError):
            return None

        try:
            gen_token = self._read_token()
            gen_num = int(gen_token) if gen_token else 0
        except (ValueError, TypeError):
            gen_num = 0

        obj_token = self._read_token()
        if obj_token != b"obj":
            return None

        self._skip_whitespace()
        value = self._parse_value()

        if value is None:
            return None

        # Check if this is a stream object
        self._skip_whitespace()
        peek = self._peek_token()
        if peek == b"stream":
            self._skip_token()
            self._skip_whitespace()
            # Consume 'stream' keyword line ending
            if self.data[self.pos : self.pos + 1] == b"\r":
                self.pos += 1
            if self.data[self.pos : self.pos + 1] == b"\n":
                self.pos += 1
            elif self.data[self.pos : self.pos + 2] == b"\r\n":
                self.pos += 2

            # Find 'endstream'
            end_idx = self.data.find(b"endstream", self.pos)
            if end_idx == -1:
                end_idx = self.length
            stream_data = self.data[self.pos : end_idx]
            self.pos = end_idx + 9  # len("endstream")

            # Try to get stream length from dictionary
            stream_dict = value.value if value.type == ObjectType.DICTIONARY else {}
            stream_obj = PDFObject(
                type=ObjectType.STREAM,
                value=stream_dict,
                obj_num=obj_num,
                gen_num=gen_num,
                stream_data=stream_data,
                stream_dict=stream_dict,
            )
            return stream_obj

        return PDFObject(
            type=value.type,
            value=value.value,
            obj_num=obj_num,
            gen_num=gen_num,
        )

    def _parse_value(self) -> PDFObject | None:
        """Parse any PDF value based on first byte."""
        self._skip_whitespace()
        if self.pos >= self.length:
            return None

        ch = self.data[self.pos : self.pos + 1]

        if ch == b"<" and self.data[self.pos + 1 : self.pos + 2] == b"<":
            return self._parse_dictionary()
        elif ch == b"<":
            return self._parse_hex_string()
        elif ch == b"[":
            return self._parse_array()
        elif ch == b"(":
            return self._parse_literal_string()
        elif ch == b"/":
            return self._parse_name()
        elif ch == b"t" or ch == b"f":
            return self._parse_boolean()
        elif ch == b"n":
            return self._parse_null()
        elif ch == b"(" or ch == b"/":
            pass  # handled above

        # Could be number or reference
        if ch in b"-+0123456789.":
            return self._parse_number_or_ref()

        return None

    def _parse_boolean(self) -> PDFObject:
        if self.data[self.pos : self.pos + 4] == b"true":
            self.pos += 4
            return PDFObject(type=ObjectType.BOOLEAN, value=True)
        elif self.data[self.pos : self.pos + 5] == b"false":
            self.pos += 5
            return PDFObject(type=ObjectType.BOOLEAN, value=False)
        raise PDFParseError("Invalid boolean")

    def _parse_null(self) -> PDFObject:
        if self.data[self.pos : self.pos + 4] == b"null":
            self.pos += 4
            return PDFObject(type=ObjectType.NULL, value=None)
        raise PDFParseError("Invalid null")

    def _parse_number_or_ref(self) -> PDFObject:
        """Parse a number or an indirect reference (N M R)."""
        # Read first number
        num_str = self._read_number_string()
        if num_str is None:
            return PDFObject(type=ObjectType.NUMBER, value=0)

        # Peek to see if there's another number followed by 'R'
        saved = self.pos
        self._skip_whitespace()
        peek = self._peek_token()

        if peek and re.match(rb"\d+$", peek):
            num2 = int(peek)
            self._skip_token()
            self._skip_whitespace()
            peek2 = self._peek_token()
            if peek2 == b"R":
                self._skip_token()
                return PDFObject(type=ObjectType.REF, value=(int(num_str), num2))
            else:
                self.pos = saved

        try:
            if "." in num_str or "e" in num_str.lower():
                return PDFObject(type=ObjectType.NUMBER, value=float(num_str))
            return PDFObject(type=ObjectType.NUMBER, value=int(num_str))
        except ValueError:
            return PDFObject(type=ObjectType.NUMBER, value=0)

    def _parse_literal_string(self) -> PDFObject:
        """Parse a literal string ( ... )."""
        self.pos += 1  # skip (
        result = []
        depth = 1
        while self.pos < self.length and depth > 0:
            ch = self.data[self.pos : self.pos + 1]
            if ch == b"\\":
                self.pos += 1
                esc = self.data[self.pos : self.pos + 1]
                if esc == b"n":
                    result.append(b"\n")
                elif esc == b"r":
                    result.append(b"\r")
                elif esc == b"t":
                    result.append(b"\t")
                elif esc == b"\\":
                    result.append(b"\\")
                elif esc == b"(":
                    result.append(b"(")
                elif esc == b")":
                    result.append(b")")
                elif esc in b"01234567":
                    # Octal escape
                    octal = esc
                    for _ in range(2):
                        self.pos += 1
                        next_ch = self.data[self.pos : self.pos + 1]
                        if next_ch in b"01234567":
                            octal += next_ch
                        else:
                            break
                    result.append(bytes([int(octal, 8)]))
                    self.pos += 1
                    continue
                else:
                    result.append(esc)
                self.pos += 1
            elif ch == b"(":
                depth += 1
                result.append(b"(")
                self.pos += 1
            elif ch == b")":
                depth -= 1
                if depth > 0:
                    result.append(b")")
                self.pos += 1
            else:
                result.append(ch)
                self.pos += 1

        return PDFObject(type=ObjectType.STRING_LITERAL, value=b"".join(result))

    def _parse_hex_string(self) -> PDFObject:
        """Parse a hex string < ... >."""
        self.pos += 1  # skip <
        hex_chars = []
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch == b">":
                self.pos += 1
                break
            if ch in b"0123456789abcdefABCDEF":
                hex_chars.append(ch[0])
            self.pos += 1

        hex_str = bytes(hex_chars).decode("ascii")
        if len(hex_str) % 2:
            hex_str += "0"
        return PDFObject(type=ObjectType.STRING_HEX, value=bytes.fromhex(hex_str))

    def _parse_name(self) -> PDFObject:
        """Parse a name object /Name."""
        self.pos += 1  # skip /
        start = self.pos
        # Keep the / prefix in the value for consistent key lookups
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch in b" \t\n\r()<>[ ]{}=/":
                break
            self.pos += 1
        name = self.data[start : self.pos]
        # Decode hex escapes like #20
        decoded = bytearray()
        i = 0
        while i < len(name):
            if name[i : i + 1] == b"#" and i + 2 < len(name):
                try:
                    decoded.append(int(name[i + 1 : i + 3], 16))
                    i += 3
                except ValueError:
                    decoded.append(name[i])
                    i += 1
            else:
                decoded.append(name[i])
                i += 1
        return PDFObject(type=ObjectType.NAME, value=b"/" + bytes(decoded))

    def _parse_array(self) -> PDFObject:
        """Parse an array [ ... ]."""
        self.pos += 1  # skip [
        elements = []
        self._skip_whitespace()
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch == b"]":
                self.pos += 1
                break
            self._skip_whitespace()
            val = self._parse_value()
            if val is not None:
                elements.append(val)
            self._skip_whitespace()
        return PDFObject(type=ObjectType.ARRAY, value=elements)

    def _parse_dictionary(self) -> PDFObject:
        """Parse a dictionary << ... >>."""
        self.pos += 2  # skip <<
        entries = {}
        self._skip_whitespace()
        while self.pos < self.length:
            self._skip_whitespace()
            if self.data[self.pos : self.pos + 2] == b">>":
                self.pos += 2
                break
            # Parse key (must be a name)
            key = self._parse_value()
            if key is None or key.type != ObjectType.NAME:
                break
            # Parse value
            self._skip_whitespace()
            val = self._parse_value()
            if val is None:
                break
            entries[key.value] = val
        return PDFObject(type=ObjectType.DICTIONARY, value=entries)

    # --- Utility methods ---

    def _skip_whitespace(self):
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch in b" \t\n\r\x00":
                self.pos += 1
            elif ch == b"%":
                # Skip comment
                self.pos += 1
                while self.pos < self.length and self.data[self.pos : self.pos + 1] not in b"\n\r":
                    self.pos += 1
            else:
                break

    def _read_token(self) -> bytes | None:
        """Read the next whitespace-delimited token."""
        self._skip_whitespace()
        if self.pos >= self.length:
            return None
        start = self.pos
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch in b" \t\n\r()<>[]{}/%":
                break
            self.pos += 1
        token = self.data[start : self.pos]
        return token if token else None

    def _peek_token(self) -> bytes | None:
        """Peek at the next token without advancing."""
        saved = self.pos
        token = self._read_token()
        self.pos = saved
        return token

    def _skip_token(self):
        """Skip the next token."""
        self._read_token()

    def _read_line(self) -> bytes:
        """Read until end of line."""
        start = self.pos
        while self.pos < self.length:
            ch = self.data[self.pos : self.pos + 1]
            if ch in b"\n\r":
                line = self.data[start : self.pos]
                # Skip line ending
                if self.data[self.pos : self.pos + 2] == b"\r\n":
                    self.pos += 2
                else:
                    self.pos += 1
                return line
            self.pos += 1
        return self.data[start:]

    def _read_number_string(self) -> str | None:
        """Read a number as a string."""
        self._skip_whitespace()
        start = self.pos
        if self.pos < self.length and self.data[self.pos : self.pos + 1] in b"-+":
            self.pos += 1
        while self.pos < self.length and self.data[self.pos : self.pos + 1] in b"0123456789.":
            self.pos += 1
        if self.pos < self.length and self.data[self.pos : self.pos + 1] in b"eE":
            self.pos += 1
            if self.pos < self.length and self.data[self.pos : self.pos + 1] in b"-+":
                self.pos += 1
            while self.pos < self.length and self.data[self.pos : self.pos + 1] in b"0123456789":
                self.pos += 1
        num_str = self.data[start : self.pos].decode("ascii", errors="ignore")
        return num_str if num_str else None


def parse_pdf(data: bytes) -> ParsedPDF:
    """Parse raw PDF bytes into a ParsedPDF structure."""
    parser = PDFParser(data)
    return parser.parse()


def parse_pdf_file(path: str | Path) -> ParsedPDF:
    """Parse a PDF file from disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    return parse_pdf(p.read_bytes())
