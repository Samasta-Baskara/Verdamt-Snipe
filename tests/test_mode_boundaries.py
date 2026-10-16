"""Mode boundary contract tests (redesign 2026-10-16).

Locks the per-mode design that was agreed explicitly:

- Mode 2 (app) does NOT run the heavy Katana crawler — DeepCrawler only.
- Katana lives in the assault-class modes (3/4/5) via the shared
  ``run_katana_phase`` helper (one implementation, not three copies).
- Mode 3 enrichment (Auto-Recon / Katana Crawl / Auto-App) is an official,
  visible pipeline phase set — not hidden behavior — and its runtime ph()
  labels resolve to those exact stages.
- Mode 5 (full) composes 1 -> Katana -> 2 -> WAF -> 3 -> 4 (poisoning
  included, POST-body probes only live there).
- WAF/origin hunting is a single shared phase used by modes 2/3/5.
- ``--passive`` blocks mode 7 (nuclei) instead of returning silent zero
  findings.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestModeBoundaries(unittest.TestCase):
    def _src(self, rel: str) -> str:
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_mode2_has_no_katana_and_uses_deepcrawler(self):
        app = self._src("runners/app_analysis.py")
        self.assertNotIn("run_katana", app)
        self.assertIn("DeepCrawler", app)

    def test_katana_home_is_assault_class(self):
        # Shared helper dipakai mode 3 (cli_parser), 4 (orchestrator),
        # dan 5 (full assault).
        self.assertIn("run_katana_phase", self._src("core/cli_parser.py"))
        self.assertIn("run_katana_phase",
                      self._src("runners/poison/orchestrator.py"))
        self.assertIn("run_katana_phase", self._src("runners/full_assault.py"))

    def test_mode3_enrichment_is_official_and_visible(self):
        from core.ui.banner import _PIPELINE_STAGES_BY_MODE
        names = [s["name"] for s in _PIPELINE_STAGES_BY_MODE["ASSAULT"]]
        for phase in ("Auto-Recon", "Katana Crawl", "Auto-App"):
            self.assertIn(phase, names)
        # Label ph() runtime harus memetakan ke stage yang sama.
        cli = self._src("core/cli_parser.py")
        for label in ("AUTO-RECON:", "KATANA CRAWL:", "AUTO-APP:"):
            self.assertIn(label, cli)

    def test_full_composes_recon_to_poisoning(self):
        full = self._src("runners/full_assault.py")
        for token in ("run_recon_intel", "run_katana_phase", "run_app_analysis",
                      "run_waf_origin_phase", "run_vuln_assault",
                      "run_poison_assault"):
            self.assertIn(token, full)
        from core.ui.banner import _PIPELINE_STAGES_BY_MODE
        names = [s["name"] for s in _PIPELINE_STAGES_BY_MODE["FULL"]]
        for phase in ("Katana Crawl", "WAF / Origin Hunt",
                      "Poisoning Wave Loop"):
            self.assertIn(phase, names)

    def test_poisoning_seed_crawl_visible(self):
        from core.ui.banner import _PIPELINE_STAGES_BY_MODE
        names = [s["name"] for s in _PIPELINE_STAGES_BY_MODE["POISONING"]]
        self.assertIn("Seed Crawl", names)

    def test_waf_phase_single_implementation(self):
        shared = self._src("runners/shared.py")
        self.assertIn("async def run_waf_origin_phase", shared)
        # Mode 2/3/5 memakai helper bersama; blok hunt_origin salinan hilang.
        for rel in ("core/cli_parser.py", "runners/full_assault.py"):
            self.assertNotIn("from modules.waf.origin_hunter import hunt_origin",
                             self._src(rel))

    def test_passive_gate_blocks_nuclei(self):
        cli = self._src("core/cli_parser.py")
        self.assertIn('"poisoning", "full", "nuclei"', cli)


class TestPhaseStageAlignment(unittest.TestCase):
    """Runtime ph() labels resolve to the correct pipeline stage."""

    def tearDown(self):
        from core.ui.tables import ScanDashboard
        ScanDashboard._instance = None

    def _dash(self, mode):
        from core.ui.tables import ScanDashboard
        from core.ui.banner import _PIPELINE_STAGES_BY_MODE
        ScanDashboard._instance = None
        dash = ScanDashboard.get_instance()
        dash.pipeline = [dict(s) for s in _PIPELINE_STAGES_BY_MODE[mode]]
        return dash

    def test_assault_enrichment_phases_light_their_stages(self):
        dash = self._dash("ASSAULT")
        for phase, expected in (
            ("AUTO-RECON: Collecting intel before assault", "Auto-Recon"),
            ("KATANA CRAWL: Expanding endpoint & parameter corpus", "Katana Crawl"),
            ("AUTO-APP: Analyzing application structure", "Auto-App"),
            ("WAF DETECTED: Running origin IP hunt", "WAF / Origin Hunt"),
        ):
            dash.set_phase(phase)
            active = [s["name"] for s in dash.pipeline if s["status"] == "active"]
            self.assertEqual(active, [expected], f"{phase} -> {active}")

    def test_seed_crawl_phase_and_skip_marking(self):
        dash = self._dash("POISONING")
        dash.set_phase("SEED CRAWL: Corpus tipis — Katana seeding endpoints")
        active = [s["name"] for s in dash.pipeline if s["status"] == "active"]
        self.assertEqual(active, ["Seed Crawl"])
        # Fase kondisional yang tidak dijalankan ditandai terpisah dari
        # "completed"; mark hanya boleh menyentuh pending/active.
        dash.mark_stage_status("skipped", "seed crawl")
        status = next(s["status"] for s in dash.pipeline
                      if s["name"] == "Seed Crawl")
        self.assertEqual(status, "skipped")

    def test_full_poison_phase_targets_wave_loop(self):
        dash = self._dash("FULL")
        dash.set_phase("POISON MODE: Event-Driven Orchestrator")
        active = [s["name"] for s in dash.pipeline if s["status"] == "active"]
        self.assertEqual(active, ["Poisoning Wave Loop"])

    def test_mode2_crawl_phase_targets_deep_crawl(self):
        dash = self._dash("APP")
        dash.set_phase("DEEP CRAWL: Mapping application endpoints (DeepCrawler + Browser)")
        active = [s["name"] for s in dash.pipeline if s["status"] == "active"]
        self.assertEqual(active, ["Deep Crawl"])


if __name__ == "__main__":
    unittest.main()
