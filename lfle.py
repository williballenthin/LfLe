#!/usr/bin/python
# By Willi Ballenthin
# <william.ballenthin@mandiant.com>
#
# Recover event log entries from an image
#   by heurisitically looking for record structures.
#
# Dependencies:
#   argparse (easy_install/pip)

import sys
import struct

import argparse

isVerbose = False
isStatus = True


def debug(s):
    global verbose
    if isVerbose:
        print "# [d] %s" % (s)


def print_status(s):
    global status
    if isStatus:
        sys.stdout.write(s)


class LfleException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
            return "LfleException: %s" % (self.value)


class InvalidContents(LfleException):
    def __init__(self, value):
        super(InvalidContents, self).__init__(value)

    def __str__(self):
        return "InvalidContents: %s" % (self.value)


class InvalidStructure(LfleException):
    def __init__(self, value):
        super(InvalidStructure, self).__init__(value)

    def __str__(self):
        return "InvalidStructure: %s" % (self.value)


def doit(filename, outputfilename):
    BUFSIZE = 4096 * 1000
    MAXRECORD = 4096 * 16
    MINRECORD = 0x30
    o = open(outputfilename, "wb")

    # 0000   30 00 00 00 4C 66 4C 65 01 00 00 00 01 00 00 00    0...LfLe........
    # 0010   30 00 00 00 30 00 00 00 01 00 00 00 00 00 00 00    0...0...........
    # 0020   00 00 01 00 00 00 00 00 80 51 01 00 30 00 00 00    .........Q..0...
    #
    # 0x0 (dword)length	0x30
    # 0x4 (string)signature	LfLe
    # 0x8 (dword)major_version	0x1
    # 0xc (dword)minor_version	0x1
    # 0x10 (dword)start_offset	0x30
    # 0x14 (dword)end_offset	0x30
    # 0x18 (dword)current_record_number	0x1
    # 0x1c (dword)oldest_record_number	0x0
    # 0x20 (dword)max_size	0x10000
    # 0x24 (dword)flags	0x0
    # 0x28 (dword)retention	0x15180
    # 0x2c (dword)end_length	0x30
    o.write("0\x00\x00\x00LfLe\x01\x00\x00\x00\x01\x00\x00\x000\x00\x00\x000\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x80Q\x01\x000\x00\x00\x00")

    # 0000   28 00 00 00 11 11 11 11 22 22 22 22 33 33 33 33    (.......""""3333
    # 0010   44 44 44 44 30 00 00 00 B8 5F 00 00 65 00 00 00    DDDD0...._..e...
    # 0020   01 00 00 00 28 00 00 00                            ....(...
    #
    # 0x0 (dword)length	0x28
    # 0x4 (qword)signature1	0x2222222211111111
    # 0xc (qword)signature2	0x4444444433333333
    # 0x14 (dword)start_offset	0x30
    # 0x18 (dword)next_offset	0x58
    # 0x1c (dword)current_record_number	0x1
    # 0x20 (dword)oldest_record_number	0x1
    o.write("(\x00\x00\x00\x11\x11\x11\x11\"\"\"\"3333DDDD0\x00\x00\x00\x58\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00(\x00\x00\x00")

    def write_buf(buf):
        if buf.count("LfLe") > 1:
            raise InvalidContents("More than 1 magic in copy!")
        head = buf[:4]
        tail = buf[-4:]
        if head != tail:
            raise InvalidStructure("Invalid structure")
        o.write(buf)

    def write_offset(offset, length):
        with open(filename) as f:
            f.seek(offset)
            buf = f.read(length)
            if buf.count("LfLe") > 1:
                raise InvalidContents("More than 1 magic in write!")
            head = buf[:4]
            tail = buf[-4:]
            if head != tail:
                raise InvalidStructure("Invalid structure")
            o.write(buf)

    def get_buf():
        f = open(filename, "rb")
        f.seek(0, 2)  # end
        size = f.tell()
        f.seek(0)     # begin
        offset = 0
        counter = 0
        status = ""
        while True:
            f.seek(offset)
            buf = f.read(2 * BUFSIZE)
            if buf == "":
                break
            counter += 1

            print_status("\b" * len(status))
            status = "%s%% done" % (str(100 * float(offset) / size))
            print_status(status)
            sys.stdout.flush()

            yield (buf, offset, counter)
            offset += BUFSIZE
        print_status("\b" * len(status))
        status = "100% complete"
        print_status(status)
        sys.stdout.flush()

        f.close()

    skipped_large = 0
    skipped_small = 0
    skipped_structure = 0
    skipped_contents = 0
    records = []
    for (buf, buf_offset, counter) in get_buf():
        debug("new buffer @ %s" % (hex(buf_offset)))
        if counter % 25600 == 0:
            print_status(".")
        offset = 4
        new = True
        while True:
            debug("searching from %s to %s" % \
                      (hex(offset), hex(BUFSIZE + 4)))
            index = buf.find("LfLe", offset, BUFSIZE + 4)
            if index == -1:
                break
            if index != offset and not new:
                debug("slack space @ %s with length %s" % \
                          (hex(offset), hex(index - offset)))
            new = False
            length = struct.unpack_from("<I", buf, index - 4)[0]
            if length <= MINRECORD:  # evt file header
                skipped_small += 1
                offset = index + 1
                continue
            if length > MAXRECORD:
                debug("length too long %s > %s" % \
                        (hex(length), hex(MAXRECORD)))
                skipped_large += 1
                offset = index + 1
                continue
            records.append((buf_offset + index, length))
            if offset + length < BUFSIZE:
                debug("copying from %s (%s) with length %s" % \
                        (hex(index - 4), hex(buf_offset + index - 4), length))
                try:
                    write_buf(buf[index - 4:index - 4 + length])
                except InvalidContents:
                    skipped_contents += 1
                    debug("More than 1 magic in copy!")
                except InvalidStructure:
                    skipped_structure += 1
                    debug("Invalid structure")
            else:
                debug("writing %s with length %s" % \
                          (hex(buf_offset + index - 4), hex(length)))
                try:
                    write_offset(buf_offset + index - 4, length)
                except InvalidContents:
                    skipped_contents += 1
                    debug("More than 1 magic in copy!")
                except InvalidStructure:
                    skipped_structure += 1
                    debug("Invalid structure")
            offset = index + length
            if offset >= BUFSIZE + 4:
                break

    print_status("\n")
    print "Wrote %d records" % len(records)
    if skipped_large > 0:
        print "Skipped %d records with length greater than %s" % \
        (skipped_large, hex(MAXRECORD))
    if skipped_small > 0:
        print "Skipped %d records with length less than %s" % \
        (skipped_small, hex(MINRECORD))
    if skipped_structure > 0:
        print "Skipped %d records with invalid structure" % \
        (skipped_structure)
    if skipped_contents > 0:
        print "Skipped %d records with invalid content" % \
        (skipped_contents)
    o.close()


def main():
    parser = argparse.ArgumentParser(
        description='Recover event log entries from an image ' +
                    'by heurisitically looking for record structures.')
    parser.add_argument('input_path', action="store",
                        help="Path to a raw (dd) image file.")
    parser.add_argument('output_path', action="store",
                        help="Path to write output file that contains " +
                        "recovered event log entries.")
    parser.add_argument('-v', action="store_true", dest="verbose",
                        help="Print debugging messages during scanning.")
    parser.add_argument('-s', action="store_true", dest="nostatus",
                        help="Disable status messages (percent complete) " +
                              "during scanning.")
    parser_results = parser.parse_args()

    if parser_results.verbose:
        global isVerbose
        isVerbose = True

    if parser_results.nostatus:
        global isStatus
        isStatus = False

    doit(parser_results.input_path, parser_results.output_path)


if __name__ == '__main__':
    main()
