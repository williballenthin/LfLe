#!/usr/bin/python
#    This file is part of LfLe.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.1
import sys
import mmap
import contextlib

from Evt.Evt import Cursor
from Evt.BinaryParser import hex_dump


def main():
    with open(sys.argv[1], 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            offset = buf.find("\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44")
            if offset == -1:
                print "Cursor not found"
                return -1
            if offset < 0x4:
                print "Cursor in unexpected location: %s" % hex(offset)
                return -2
            cursor = Cursor(buf, offset - 0x4)

            print(hex_dump(buf[cursor.offset():cursor.offset() + cursor.length()]))

            print(cursor.get_all_string(indent=0))

if __name__ == "__main__":
    main()
