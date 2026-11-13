"""Sizing component units; no vendor process, host facts or target operations."""
import math
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unbound_startup as startup


class StartupTests(unittest.TestCase):
    def test_explicit_budget_and_cpu_determine_all_vendor_sizing_inputs(self):
        selected = startup.command(256, 1)
        self.assertEqual(selected[:2], ['/bin/bash', '-c'])
        for value in ('rr_cache_size=85284181', 'msg_cache_size=42642090', 'threads=1', 'slabs=4'):
            self.assertIn("'" + value + "'", selected[2])
        self.assertIn(startup.SCRIPT_SHA256 + '  /unbound.sh', selected[2])
        self.assertIn('tail -n +34 /unbound.sh', selected[2])
        self.assertNotIn('MemAvailable', selected[2])
        self.assertNotIn('nproc', selected[2])
        self.assertEqual(startup.command(256, 0.5), selected)
        self.assertNotEqual(startup.command(512, 1), selected)
        self.assertIn("'threads=3'", startup.command(256, 4)[2])
        self.assertIn("'slabs=4'", startup.command(256, 4)[2])

    def test_invalid_budgets_and_types_refuse_before_command_generation(self):
        for memory in (None, True, 0, 24, 25.0, '256', 2**20 + 1):
            with self.subTest(memory=memory), self.assertRaises(ValueError):
                startup.command(memory, 1)
        for cpu in (None, True, 0, -1, 257, math.inf, math.nan, '1'):
            with self.subTest(cpu=cpu), self.assertRaises(ValueError):
                startup.command(256, cpu)

    def test_cache_allocation_is_bounded_by_each_selected_process_budget(self):
        for memory in (25, 64, 256, 1024):
            text = startup.command(memory, 1)[2]
            available = memory * 1024**2 - startup.RESERVED_BYTES
            rr, msg = available // 3, (available // 3) // 2
            self.assertLess(rr + msg + startup.RESERVED_BYTES, memory * 1024**2)
            self.assertIn("'rr_cache_size=" + str(rr) + "'", text)
            self.assertIn("'msg_cache_size=" + str(msg) + "'", text)


if __name__ == '__main__':
    unittest.main()
