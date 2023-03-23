# Honky Pie, a HonokaMiku/libhonoka implementation in Python
#
# Copyright (c) 2023 Dark Energy Processor
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from typing import ClassVar

from .util import calculate_md5


class DecrypterContext:
    HEADER_SIZE: ClassVar[int] = 0
    VERSION: ClassVar[int] = 0

    def decrypt_int(self, data: int) -> int:
        """Decrypt single byte represented as int.

        Args:
            data (int): Single byte to decrypt, in range of 0 inclusive to 256 exclusive.

        Returns:
            int: Decrypted byte as int.
        """
        raise NotImplementedError("Please derive")

    def goto_offset(self, pos: int) -> None:
        """Recalculate decrypter context to decrypt at specified position in the file stream.

        Args:
            pos (int): New position, starting from the start of file.

        Raises:
            NotImplementedError: Raised when seeking is not supported.
        """
        raise NotImplementedError("Please derive")

    def decrypt_block(self, data: bytes) -> bytes:
        """Decrypt bytes of data and return new bytes from it.

        Args:
            data (bytes): Data to decrypt.

        Returns:
            bytes: Decrypted data.
        """
        return bytes(map(self.decrypt_int, data))

    def emit_header(self) -> bytes:
        """Print out the file header that identify the encryption mode.

        Returns:
            bytes: Header that should be written before encrypted data.
        """
        return b""


class Version1Context(DecrypterContext):
    VERSION: ClassVar[int] = 1

    def __init__(self, prefix: bytes, filename: bytes, key_tables: list[int], header_test: bytes | None = None):
        digest, filenamelen = calculate_md5(prefix, filename)
        self.update_key = filenamelen + 1
        self.init_key = (digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]
        self.xor_key = self.init_key
        self.pos = 0

    def decrypt_int(self, data: int) -> int:
        # Same key used to decrypt 4 bytes at a time, from msb to lsb.
        index = self.pos & 3
        key = (self.xor_key >> (3 - index) * 8) & 0xFF
        result = data ^ key
        if index == 3:
            self._step()
        self.pos = self.pos + 1
        return result

    def goto_offset(self, pos: int):
        # Is it bounded?
        pos = max(pos, 0)
        currentpos4 = self.pos // 4
        newpos4 = pos // 4
        if currentpos4 == newpos4:
            # Only set pos
            self.pos = pos
            return
        # Is it forward?
        if newpos4 > currentpos4:
            for i in range(currentpos4, newpos4):
                self._step()
            self.pos = pos
            return
        # TODO: Check if it's worth starting from beginning
        # Start from beginning
        self.xor_key = self.init_key
        for i in range(newpos4):
            self._step()
        self.pos = pos

    def _step(self):
        self.xor_key = (self.xor_key + self.update_key) & 0xFFFFFFFF


class Version2Context(DecrypterContext):
    HEADER_SIZE: ClassVar[int] = 4
    VERSION: ClassVar[int] = 2

    def __init__(self, prefix: bytes, filename: bytes, key_tables: list[int], header_test: bytes | None = None):
        digest, filenamelen = calculate_md5(prefix, filename)
        if header_test is not None and digest[4:8] != header_test[:4]:
            raise ValueError("Version 2 header invalid")
        self.header = digest[4:8]
        self.init_key = ((digest[0] & 0x7F) << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]
        self.xor_key = ((self.init_key >> 23) & 0xFF) | ((self.init_key >> 7) & 0xFF00)
        self.update_key = self.init_key
        self.pos = 0

    def decrypt_int(self, data: int) -> int:
        # Same key used to decrypt 2 bytes at a time, from lsb to msb.
        index = self.pos & 1
        key = (self.xor_key >> index * 8) & 0xFF
        result = data ^ key
        if index == 1:
            self._step()
        self.pos = self.pos + 1
        return result

    def goto_offset(self, pos: int):
        # Is it bounded?
        pos = max(pos, 0)
        currentpos2 = self.pos // 2
        newpos2 = pos // 2
        if currentpos2 == newpos2:
            # Only set pos
            self.pos = pos
            return
        # Is it forward?
        if newpos2 > currentpos2:
            for i in range(currentpos2, newpos2):
                self._step()
            self.pos = pos
            return
        # TODO: Check if it's worth starting from beginning
        # Start from beginning
        self.xor_key = ((self.init_key >> 23) & 0xFF) | ((self.init_key >> 7) & 0xFF00)
        for i in range(newpos2):
            self._step()
        self.pos = pos

    def _step(self):
        a = self.update_key >> 16
        b = ((a * 0x41A70000) & 0x7FFFFFFF + (self.update_key & 0xFFFF) * 0x41A7) & 0xFFFFFFFF
        c = ((a * 0x41A7) >> 15) & 0xFFFFFFFF
        d = c + b
        e = (d - 0x7FFFFFFF) % 0x100000000
        f = e if e > 0x7FFFFFFE else d
        self.update_key = f
        self.xor_key = ((b >> 23) & 0xFF) | ((b >> 7) & 0xFF00)
