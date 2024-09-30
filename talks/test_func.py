import unittest

from func import Index, Weight, mastic_func, weighted_heavy_hitters

class TestIndex(unittest.TestCase):
    def test_is_prefx(self):
        self.assertTrue(Index(0, 0, 1).is_prefix(Index(0, 0, 1, 0)))
        self.assertFalse(Index(1, 0, 1).is_prefix(Index(0, 0, 1, 0)))
        self.assertFalse(Index(0, 0, 1, 0).is_prefix(Index(0, 0, 1)))

class TestFunc(unittest.TestCase):
    def test(self):
        measurements = [
            (Index(0, 0), Weight(23)),
            (Index(0, 1), Weight(14)),
            (Index(1, 0), Weight(1)),
            (Index(1, 0), Weight(95)),
            (Index(0, 0), Weight(1337)),
        ]

        prefixes = [
            Index(0),
            Index(1),
        ]

        r = mastic_func(measurements, prefixes)
        self.assertEqual(r[Index(0)], Weight(23 + 14 + 1337))
        self.assertEqual(r[Index(1)], Weight(1 + 95))


    def test_weighted_heavy_hitters(self):
        measurements = [
            (Index(0, 0), Weight(1)),
            (Index(0, 1), Weight(2)),
            (Index(1, 0), Weight(1)),
            (Index(1, 0), Weight(1)),
            (Index(0, 0), Weight(0)),
        ]

        r = weighted_heavy_hitters(measurements, Weight(2), 2)
        self.assertEqual(r, [Index(0, 1), Index(1, 0)])
