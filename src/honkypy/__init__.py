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


from .dctx import DecrypterContext, Version1Context, Version2Context
from .key_tables import *

from typing import Callable, Literal, Protocol, ClassVar, cast, overload


class _SupportsDctxType(Protocol):
    HEADER_SIZE: ClassVar[int]
    VERSION: ClassVar[int]

    def __init__(self, prefix: bytes, filename: bytes, key_tables: list[int], header_test: bytes | None = None):
        ...

_ValidGametypes = Literal["JP", "WW", "TW", "CN"]


NAME_PREFIX_JP = b"Hello"
NAME_PREFIX_WW = b"BFd3EnkcKa"
NAME_PREFIX_TW = b"M2o2B7i3M6o6N88"
NAME_PREFIX_CN = b"iLbs0LpvJrXm3zjdhAr4"
NAME_PREFIX_EN = NAME_PREFIX_WW


_COMBINATION: list[tuple[_ValidGametypes, bytes, list[int]]] = [
    ("JP", NAME_PREFIX_JP, KEY_TABLES_JP),
    ("WW", NAME_PREFIX_WW, KEY_TABLES_WW),
    ("TW", NAME_PREFIX_TW, KEY_TABLES_TW),
    ("CN", NAME_PREFIX_CN, KEY_TABLES_CN),
]

_GAME_VERSIONS: list[type[_SupportsDctxType]] = [
    Version1Context,
]

_GAME_VERSIONS_PROBE: list[type[_SupportsDctxType]] = [
    Version2Context,
]


def decrypt_setup_probe(filename: str | bytes, header: bytes, *, version: int = 0) -> tuple[DecrypterContext, int, _ValidGametypes]:
    # Try all combination
    for gametype, prefix, key_tables in _COMBINATION:
        try:
            dctx, headersize = decrypt_setup(filename, header, prefix, key_tables, version)
            return dctx, headersize, gametype
        except ValueError:
            pass
    raise ValueError("No suitable decryption mode found")


def decrypt_setup(
    filename: str | bytes,
    header: bytes,
    prefix: bytes,
    key_tables: list[int],
    version: int = 0,
) -> tuple[DecrypterContext, int]:
    if isinstance(filename, str):
        filename = filename.encode("UTF-8")
    if len(header) < 16:
        raise ValueError("Insufficient header data (need at least 16 bytes)")
    if version == 0:
        for context_class in _GAME_VERSIONS_PROBE:
            try:
                dctx = cast(DecrypterContext, context_class(prefix, filename, key_tables, header))
                return dctx, context_class.HEADER_SIZE
            except ValueError:
                pass
        raise ValueError("No suitable decryption game file found")
    elif version < 0 or version > len(_GAME_VERSIONS):
        raise IndexError("Version out of range")
    else:
        context_class = _GAME_VERSIONS[version - 1]
        dctx = cast(DecrypterContext, context_class(prefix, filename, key_tables, header))
        return dctx, context_class.HEADER_SIZE
