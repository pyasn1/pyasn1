#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import unittest
import sys

from tests.base import BaseTestCase

from pyasn1.compat import integer


class ZeroIntegerTestCase(BaseTestCase):
    def testZeroEncoder(self):
        assert integer.to_bytes(0, signed=True) == b'\x00'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
