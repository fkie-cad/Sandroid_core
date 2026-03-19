"""Copyright 2021-2022, CCL Forensics
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import base64
import enum
import struct
import typing
import xml.etree.ElementTree as etree  # nosec B405 # Forensic tool needs to parse Android XML files

__version__ = "0.2.0"
__description__ = "Python module to convert Android ABX binary XML files"
__contact__ = "Alex Caithness"

# See: base/core/java/com/android/internal/util/BinaryXmlSerializer.java


class AbxDecodeError(Exception):
    pass


class XmlType(enum.IntEnum):
    # These first constants are from: libcore/xml/src/main/java/org/xmlpull/v1/XmlPullParser.java
    # most of them are unused, but here for completeness
    START_DOCUMENT = 0
    END_DOCUMENT = 1
    START_TAG = 2
    END_TAG = 3
    TEXT = 4
    CDSECT = 5
    ENTITY_REF = 6
    IGNORABLE_WHITESPACE = 7
    PROCESSING_INSTRUCTION = 8
    COMMENT = 9
    DOCDECL = 10

    ATTRIBUTE = 15


class DataType(enum.IntEnum):
    TYPE_NULL = 1 << 4
    TYPE_STRING = 2 << 4
    TYPE_STRING_INTERNED = 3 << 4
    TYPE_BYTES_HEX = 4 << 4
    TYPE_BYTES_BASE64 = 5 << 4
    TYPE_INT = 6 << 4
    TYPE_INT_HEX = 7 << 4
    TYPE_LONG = 8 << 4
    TYPE_LONG_HEX = 9 << 4
    TYPE_FLOAT = 10 << 4
    TYPE_DOUBLE = 11 << 4
    TYPE_BOOLEAN_TRUE = 12 << 4
    TYPE_BOOLEAN_FALSE = 13 << 4


class AbxReader:
    MAGIC = b"ABX\x00"

    def _read_raw(self, length):
        buff = self._stream.read(length)
        if len(buff) < length:
            raise ValueError(
                f"couldn't read enough data at offset: {self._stream.tell() - len(buff)}"
            )
        return buff

    def _read_byte(self):
        buff = self._read_raw(1)
        return buff[0]

    def _read_short(self):
        buff = self._read_raw(2)
        return struct.unpack(">h", buff)[0]

    def _read_int(self):
        buff = self._read_raw(4)
        return struct.unpack(">i", buff)[0]

    def _read_long(self):
        buff = self._read_raw(8)
        return struct.unpack(">q", buff)[0]

    def _read_float(self):
        buff = self._read_raw(4)
        return struct.unpack(">f", buff)[0]

    def _read_double(self):
        buff = self._read_raw(8)
        return struct.unpack(">d", buff)[0]

    def _read_string_raw(self):
        length = self._read_short()
        if length < 0:
            raise ValueError(
                f"Negative string length at offset {self._stream.tell() - 2}"
            )
        buff = self._read_raw(length)
        return buff.decode("utf-8")

    def _read_interned_string(self):
        reference = self._read_short()
        if reference == -1:
            value = self._read_string_raw()
            self._interned_strings.append(value)
        else:
            value = self._interned_strings[reference]
        return value

    def __init__(self, stream: typing.BinaryIO):
        self._interned_strings = []
        self._stream = stream

    # ------------------------------------------------------------------
    # Token handler helpers (extracted from read() to reduce nesting)
    # ------------------------------------------------------------------

    def _handle_start_document(self, token: int, offset: int, document_opened: bool) -> bool:
        """Handle a START_DOCUMENT token.

        Validates that the data type is TYPE_NULL and that the document
        has not already been opened.

        Returns:
            Updated document_opened flag (always True on success).
        """
        if token & 0xF0 != DataType.TYPE_NULL:
            raise AbxDecodeError(
                f"START_DOCUMENT with an invalid data type at offset {offset} - 1"
            )
        if document_opened:
            raise AbxDecodeError(
                f"Unexpected START_DOCUMENT at offset {offset}"
            )
        return True

    def _handle_end_document(
        self, token: int, offset: int, element_stack: list, document_opened: bool, is_multi_root: bool
    ) -> None:
        """Handle an END_DOCUMENT token.

        Validates data type, stack state, and that the document was opened.

        Raises:
            AbxDecodeError: On any validation failure.
        """
        if token & 0xF0 != DataType.TYPE_NULL:
            raise AbxDecodeError(
                f"END_DOCUMENT with an invalid data type at offset {offset}"
            )
        if not (
            len(element_stack) == 0
            or (len(element_stack) == 1 and is_multi_root)
        ):
            raise AbxDecodeError(
                f"END_DOCUMENT with unclosed elements at offset {offset}"
            )
        if not document_opened:
            raise AbxDecodeError(
                f"END_DOCUMENT before document started at offset {offset}"
            )

    def _handle_start_tag(
        self, token: int, offset: int, element_stack: list, document_opened: bool, root_closed: bool
    ) -> etree.Element:
        """Handle a START_TAG token.

        Validates the token, reads the tag name, creates the element, and
        pushes it onto the stack.

        Returns:
            The newly created element (which is the root if the stack was empty).
        """
        if token & 0xF0 != DataType.TYPE_STRING_INTERNED:
            raise AbxDecodeError(
                f"START_TAG with an invalid data type at offset {offset}"
            )
        if not document_opened:
            raise AbxDecodeError(
                f"START_TAG before document started at offset {offset}"
            )
        if root_closed:
            raise AbxDecodeError(
                f"START_TAG after root was closed started at offset {offset}"
            )

        tag_name = self._read_interned_string()
        if len(element_stack) == 0:
            element = etree.Element(tag_name)
        else:
            element = etree.SubElement(element_stack[-1], tag_name)
        element_stack.append(element)
        return element

    def _handle_end_tag(
        self, token: int, offset: int, element_stack: list, is_multi_root: bool
    ) -> tuple[bool, etree.Element]:
        """Handle an END_TAG token.

        Validates the token and tag name, pops the element from the stack.

        Returns:
            Tuple of (root_closed, popped_element).
        """
        if token & 0xF0 != DataType.TYPE_STRING_INTERNED:
            raise AbxDecodeError(
                f"END_TAG with an invalid data type at offset {offset}"
            )
        if len(element_stack) == 0 or (
            is_multi_root and len(element_stack) == 1
        ):
            raise AbxDecodeError(
                f"END_TAG without any elements left at offset {offset}"
            )

        tag_name = self._read_interned_string()
        if element_stack[-1].tag != tag_name:
            raise AbxDecodeError(
                f"Unexpected END_TAG name at {offset}. "
                f"Expected: {element_stack[-1].tag}; got: {tag_name}"
            )

        last = element_stack.pop()
        root_closed = len(element_stack) == 0
        return root_closed, last

    def _handle_text(self, element_stack: list) -> None:
        """Handle a TEXT token.

        Reads the text value and appends it to the current element's text
        content. Whitespace-only text is silently discarded when the element
        already contains child elements.

        Raises:
            NotImplementedError: If the element has both child elements and
                non-whitespace text (mixed content).
        """
        value = self._read_string_raw()
        current = element_stack[-1]

        if len(current):
            if len(value.strip()) == 0:
                return  # layout whitespace can be safely discarded
            raise NotImplementedError(
                "Can't deal with elements with mixed text and element contents"
            )

        if current.text is None:
            current.text = value
        else:
            current.text += value

    def _handle_attribute(
        self, token: int, offset: int, element_stack: list, is_multi_root: bool
    ) -> None:
        """Handle an ATTRIBUTE token.

        Reads the attribute name and typed value, then sets it on the
        current element.
        """
        if len(element_stack) == 0 or (
            is_multi_root and len(element_stack) == 1
        ):
            raise AbxDecodeError(
                f"ATTRIBUTE without any elements left at offset {offset}"
            )

        attribute_name = self._read_interned_string()

        if attribute_name in element_stack[-1].attrib:
            raise AbxDecodeError(
                f"ATTRIBUTE name already in target element at offset {offset}"
            )

        value = self._read_attribute_value(token, offset)
        element_stack[-1].attrib[attribute_name] = str(value)

    def _read_attribute_value(self, token: int, offset: int):
        """Decode and return the typed value for an ATTRIBUTE token.

        Args:
            token: The raw token byte.
            offset: Stream offset for error reporting.

        Returns:
            The decoded attribute value (str, int, float, or None).
        """
        data_type = token & 0xF0

        if data_type == DataType.TYPE_NULL:
            return None
        if data_type == DataType.TYPE_BOOLEAN_TRUE:
            return "true"
        if data_type == DataType.TYPE_BOOLEAN_FALSE:
            return "false"
        if data_type == DataType.TYPE_INT:
            return self._read_int()
        if data_type == DataType.TYPE_INT_HEX:
            return f"{self._read_int():x}"
        if data_type == DataType.TYPE_LONG:
            return self._read_long()
        if data_type == DataType.TYPE_LONG_HEX:
            return f"{self._read_long():x}"
        if data_type == DataType.TYPE_FLOAT:
            return self._read_float()
        if data_type == DataType.TYPE_DOUBLE:
            return self._read_double()
        if data_type == DataType.TYPE_STRING:
            return self._read_string_raw()
        if data_type == DataType.TYPE_STRING_INTERNED:
            return self._read_interned_string()
        if data_type == DataType.TYPE_BYTES_HEX:
            length = self._read_short()
            return self._read_raw(length).hex()
        if data_type == DataType.TYPE_BYTES_BASE64:
            length = self._read_short()
            return base64.encodebytes(self._read_raw(length)).decode().strip()

        raise AbxDecodeError(
            f"Unexpected attribute datatype at offset: {offset}"
        )

    # ------------------------------------------------------------------
    # Main public API
    # ------------------------------------------------------------------

    def read(self, *, is_multi_root=False):
        """Read the ABX file.

        :param is_multi_root: some xml files on Android contain multiple root
            elements making reading them using a document model problematic.
            For these files, set is_multi_root to True and the output
            ElementTree will wrap the elements in a single "root" element.
        :return: ElementTree representation of the data.
        """
        magic = self._read_raw(len(AbxReader.MAGIC))
        if magic != AbxReader.MAGIC:
            raise ValueError(
                f"Invalid magic. Expected {AbxReader.MAGIC.hex()}; got: {magic.hex()}"
            )

        document_opened = False
        root_closed = False
        root = None
        element_stack = []  # ElementTree doesn't support parents so we maintain a stack
        if is_multi_root:
            root = etree.Element("root")
            element_stack.append(root)

        while True:
            token_raw = self._stream.read(1)
            if not token_raw:
                break
            token = token_raw[0]
            offset = self._stream.tell()
            xml_type = token & 0x0F

            if xml_type == XmlType.START_DOCUMENT:
                document_opened = self._handle_start_document(token, offset, document_opened)

            elif xml_type == XmlType.END_DOCUMENT:
                self._handle_end_document(token, offset, element_stack, document_opened, is_multi_root)
                break

            elif xml_type == XmlType.START_TAG:
                element = self._handle_start_tag(token, offset, element_stack, document_opened, root_closed)
                if root is None:
                    root = element

            elif xml_type == XmlType.END_TAG:
                closed, last = self._handle_end_tag(token, offset, element_stack, is_multi_root)
                if closed:
                    root_closed = True
                    root = last

            elif xml_type == XmlType.TEXT:
                self._handle_text(element_stack)

            elif xml_type == XmlType.ATTRIBUTE:
                self._handle_attribute(token, offset, element_stack, is_multi_root)

            else:
                raise NotImplementedError(f"unexpected XML type: {xml_type}")

        if not (
            root_closed
            or (is_multi_root and len(element_stack) == 1 and element_stack[0] is root)
        ):
            raise AbxDecodeError(
                "Elements still in the stack when completing the document"
            )

        if root is None:
            raise AbxDecodeError("Document was never assigned a root element")

        return etree.ElementTree(root)


def main(args):
    in_path = pathlib.Path(args[0])
    multi_root = "-mr" in args[1:]
    with in_path.open("rb") as f:
        reader = AbxReader(f)
        doc = reader.read(is_multi_root=multi_root)

    print(etree.tostring(doc.getroot()).decode())


if __name__ == "__main__":
    import pathlib
    import sys

    main(sys.argv[1:])
