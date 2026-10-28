#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
def to_bytes(value, signed=False, length=0):
    length = max(value.bit_length(), length)
    if length == 0 and signed:
        length = 1  # we want at least 1 bit to correctly represent 0

    high_bit_set = length > 0 and ((value >> (length - 1)) & 1) != 0 or False

    if signed and (value >= 0 and high_bit_set or value < 0 and not high_bit_set):
        length += 1  # add room for the sign bit

    return value.to_bytes((length + 7) // 8, 'big', signed=signed)
