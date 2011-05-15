#!/usr/bin/env python
#
# Copyright 2011, Toru Maesaka
#
# Redistribution and use of this source code is licensed under
# the BSD license. See COPYING file for license description.
#
# Kyoto Tycoon should be started like this:
#   $ ktserver one.kch two.kch three.kch

import config
import time
import unittest
from kyototycoon import KyotoTycoon

DB_1 = 'one.kch'
DB_2 = 'two.kch'
DB_INVALID = 'three.kch'

class UnitTest(unittest.TestCase):
    def setUp(self):
        self.kt_handle = KyotoTycoon()
        self.kt_handle.open()
        self.LARGE_KEY_LEN = 8000

    def test_status(self):
        status = self.kt_handle.status(DB_1)
        assert status is not None

        status = self.kt_handle.status(DB_2)
        assert status is not None

        status = self.kt_handle.status(DB_INVALID)
        assert status is None

        status = self.kt_handle.status('non_existent')
        assert status is None

    def test_set_get(self):
        self.assertTrue(self.kt_handle.clear())

        self.assertTrue(self.kt_handle.set('ice', 'cream', db=DB_2))
        self.assertFalse(self.kt_handle.set('palo', 'alto', db=DB_INVALID))

        assert self.kt_handle.get('ice') is None
        assert self.kt_handle.get('ice', db=DB_1) is None
        assert self.kt_handle.get('ice', db=DB_INVALID) is None

        self.assertEqual(self.kt_handle.get('ice', db='two.kch'), 'cream')
        self.assertEqual(self.kt_handle.count(db=DB_1), 0)
        self.assertEqual(self.kt_handle.count(db=DB_2), 1)

        self.assertTrue(self.kt_handle.set('frozen', 'yoghurt', db=DB_1))
        self.assertEqual(self.kt_handle.count(db=DB_1), 1)

        self.assertEqual(self.kt_handle.get('frozen'), 'yoghurt')
        self.assertEqual(self.kt_handle.get('frozen', db=DB_1), 'yoghurt')
        assert self.kt_handle.get('frozen', db=DB_2) is None
        assert self.kt_handle.get('frozen', db=DB_INVALID) is None

if __name__ == '__main__':
    unittest.main()