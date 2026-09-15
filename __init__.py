"""SysTorch -- Static Analysis & Reverse Engineering Difficulty Estimator.

Modular architecture:
  pe_structure.py   -- PEStructureAnalyzer  (sections, imports, TLS, overlay, hashes)
  obfuscation.py    -- ObfuscationAnalyzer  (strings, cipher/base64 detection)
  protectors.py     -- ProtectorSignatureAnalyzer (known packers, optional YARA)
  behavior.py       -- BehaviorAnalyzer     (attack-pattern clustering, MITRE ATT&CK)
  scoring.py         -- DifficultyScorer     (score, approach advisor, correlation)
  summary.py         -- ExecutiveSummary     (dashboard data)
  report_html.py     -- HTML report generation
  config.py          -- externalized JSON rule loading
  logutil.py          -- logging / exception-handling conventions
  ui.py               -- terminal display, traffic-light colors, --fast/--quiet timing
  art.py              -- ASCII art assets
  cli.py              -- argparse entry point, orchestration, interactive menu
"""

__version__ = "2.0.0"
