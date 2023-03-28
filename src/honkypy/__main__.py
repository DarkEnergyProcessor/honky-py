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

import argparse
import io

from . import decrypt_setup_probe, StreamIOWrapper
from .error import HonkyPyError


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--detect", "-d", action="store_true", help="Detect game decryption type as exit code.")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", nargs="?", default=None, help="Output file path")
    return parser.parse_args()


def main() -> int:
    args = get_args()
    with open(args.input, "rb") as f:
        if args.detect:
            try:
                dctx, _ = decrypt_setup_probe(args.input, f.read(16))
                return dctx.VERSION
            except HonkyPyError:
                return 0
        else:
            dctx, _ = decrypt_setup_probe(args.input, f.read(16))
            f.seek(dctx.HEADER_SIZE, io.SEEK_SET)
            decrypted_data = dctx.decrypt_block(f.read())
    with open(args.output or args.input, "wb") as f:
        f.write(decrypted_data)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
