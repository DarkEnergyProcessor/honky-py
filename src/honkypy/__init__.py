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

"""
HonkyPy, a HonokaMiku/libhonoka implementation in Python.

This module provides "a certain idol rhythm game" file encryption and decryption
routines written in pure Python.
"""


from .dctx import DecrypterContext, Version1Context, Version2Context, setup_v3
from .key_tables import *

from typing import Callable, Literal, cast


_SupportsDctxType = Callable[[bytes, bytes, list[int] | None, bytes | None], DecrypterContext]
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

_GAME_VERSIONS: list[type[_SupportsDctxType]] = [Version1Context, Version2Context, setup_v3]

_GAME_VERSIONS_PROBE: list[type[_SupportsDctxType]] = [Version2Context, setup_v3]


def decrypt_setup_probe(
    filename: str | bytes, header: bytes, *, version: int = 0
) -> tuple[DecrypterContext, _ValidGametypes]:
    # Try all combination
    for gametype, prefix, key_tables in _COMBINATION:
        try:
            dctx = decrypt_setup(prefix, filename, header, key_tables, version)
            return dctx, gametype
        except ValueError:
            pass
    raise ValueError("No suitable decryption mode found")


def decrypt_setup(
    prefix: bytes,
    filename: str | bytes,
    header: bytes,
    key_tables: list[int],
    version: int = 0,
) -> DecrypterContext:
    if isinstance(filename, str):
        filename = filename.encode("UTF-8")
    if len(header) < 16:
        raise ValueError("Insufficient header data (need at least 16 bytes)")
    if version == 0:
        for context_class in _GAME_VERSIONS_PROBE:
            try:
                dctx = cast(DecrypterContext, context_class(prefix, filename, key_tables, header))
                return dctx
            except ValueError:
                pass
        raise ValueError("No suitable decryption game file found")
    elif version < 0 or version > len(_GAME_VERSIONS):
        raise IndexError("Version out of range")
    else:
        context_class = _GAME_VERSIONS[version - 1]
        dctx = cast(DecrypterContext, context_class(prefix, filename, key_tables, header))
        return dctx


def encrypt_setup(
    prefix: bytes,
    filename: str | bytes,
    version: int,
    *,
    v3_flip_key: bool = False,
    v3_key_tables: list[int] | None = None,
    v4_lcg_index: int = 0,
):
    if isinstance(filename, str):
        filename = filename.encode("UTF-8")
    if version < 0:
        raise ValueError("Cannot encrypt version 0")
    if version == 1:
        return Version1Context(prefix, filename, [])
    elif version == 2:
        return Version2Context(prefix, filename, [])
    elif version >= 3:
        if version == 3 and v3_key_tables is None:
            raise ValueError("V3 requires key tables")


def encrypt_setup_by_gametype(
    gametype: str,
    filename: str | bytes,
    version: int,
    *,
    v3_flip_key: bool = False,
    v4_lcg_index: int = 0,
):
    for gt, prefix, key_tables in _COMBINATION:
        if gametype == gt:
            return encrypt_setup(
                prefix, filename, version, v3_flip_key=v3_flip_key, v3_key_tables=key_tables, v4_lcg_index=v4_lcg_index
            )
    raise ValueError(f"Invalid game type'{gametype}'")
