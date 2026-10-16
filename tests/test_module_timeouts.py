import asyncio
import time
import unittest
from unittest.mock import AsyncMock, patch


class TestModuleTimeouts(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_membatasi_modul_dan_log(self):
        from runners import vuln_assault

        async def slow_jwt(*args, **kwargs):
            await asyncio.sleep(60)

        with patch.dict(vuln_assault.MODULE_TIMEOUTS, {"jwt": 0.3}), \
             patch("runners.vuln_assault.w") as mock_w, \
             patch("modules.web.api_auth.jwt_hunter.scan_jwt",
                   new=AsyncMock(side_effect=slow_jwt)), \
             patch("modules.web.server_side.host_header.scan_host_header",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.server_side.crlf.scan_crlf",
                   new=AsyncMock(return_value=[])), \
             patch("runners.vuln_assault.run_nuclei", return_value=[]), \
             patch("runners.vuln_assault.run_dalfox", return_value=[]):
            t0 = time.monotonic()
            findings, _wafs = await vuln_assault.run_vuln_assault(
                "example.com", [], [], {}, None, None, None,
                vuln_threads=5, module_flags=None, policy=None,
            )
            elapsed = time.monotonic() - t0

        # modul tidur 60s tapi phase harus selesai jauh sebelum itu
        self.assertLess(elapsed, 15)
        self.assertEqual(findings, [])
        msgs = [c.args[0] for c in mock_w.call_args_list if c.args]
        self.assertTrue(
            any("jwt" in m and "timed out" in m for m in msgs), msgs)

    async def test_backstop_lebih_dari_timeout_internal(self):
        from runners import vuln_assault as va
        import core.external_tools as et
        import inspect

        # backstop (MODULE_TIMEOUTS) harus lebih besar dari timeout internal
        # tool agar jalur partial-salvage yang menang, bukan pembuangan luar.
        self.assertGreater(va.MODULE_TIMEOUTS["nuclei"],
                           inspect.signature(et.run_nuclei).parameters["timeout"].default)
        self.assertGreater(va.MODULE_TIMEOUTS["dalfox"],
                           inspect.signature(et.run_dalfox).parameters["timeout"].default)
        self.assertGreater(va.MODULE_TIMEOUTS["oob"], 60)

    def test_semua_modul_gather_punya_timeout(self):
        from runners import vuln_assault as va

        expected = {"nuclei", "dalfox", "internal_injection", "smuggling",
                    "oob", "jwt", "host_header", "crlf", "stored_xss", "idor"}
        self.assertEqual(set(va.MODULE_TIMEOUTS), expected)

    def test_kontrak_720s_per_modul(self):
        """720s per modul: cap lama bikin modul sering timeout di tengah
        jalan dan hasil terkumpul terbuang (waktu terbakar sia-sia)."""
        from runners import vuln_assault as va

        for name, limit in va.MODULE_TIMEOUTS.items():
            self.assertEqual(limit, 720, f"module {name} must get 720s")
        for name, limit in va.PRE_GATHER_TIMEOUTS.items():
            self.assertEqual(limit, 720, f"pre-gather {name} must get 720s")


if __name__ == "__main__":
    unittest.main()
