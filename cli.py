"""
Two modes:
  1. `systorch file1.exe [file2.exe ...]` -- non-interactive: runs a full
     analysis on each file in sequence and exits. combine with --fast/--quiet for scripting 50 samples without
     waiting
  2. `systorch` (no file arguments) -- interactive: boot sequence, prompt
     for a file, drop into the menu. This is the skull guy cool entrance

"""

import argparse
import glob
import os
import sys
import tempfile

import pefile

from . import ui, art
from .logutil import logger, configure_logging
from .config import load_api_rules, load_mitre_mapping, load_protector_signatures, default_yara_rules_dir
from .pe_structure import PEStructureAnalyzer
from .obfuscation import ObfuscationAnalyzer
from .protectors import ProtectorSignatureAnalyzer
from .behavior import BehaviorAnalyzer
from .scoring import DifficultyScorer
from .summary import ExecutiveSummary
from .report_html import generate_html_report

RESET = ui.RESET


class AnalysisBundle:
    """Everything needed to analyze one file, wired together once."""

    def __init__(self, path, api_rules, mitre_map, protector_sigs, yara_dir):
        try:
            self.pe = pefile.PE(path)
        except FileNotFoundError:
            raise
        except pefile.PEFormatError as e:
            raise ValueError(f"'{path}' is not a valid PE file: {e}")
        self.path = path
        self.pe_structure = PEStructureAnalyzer(self.pe, path, api_rules)
        self.obfuscation = ObfuscationAnalyzer(self.pe)
        self.protectors = ProtectorSignatureAnalyzer(self.pe, protector_sigs, yara_dir)
        self.behavior = BehaviorAnalyzer(self.pe_structure, mitre_map)
        self._progress_cb = None
        self.scorer = DifficultyScorer(self.pe_structure, self.obfuscation, self.protectors,
                                        self.behavior, progress_cb=lambda c, t, l: (
                                            self._progress_cb(c, t, l) if self._progress_cb else None))

    def set_progress_callback(self, cb):
        self._progress_cb = cb


def load_bundle(path, args):
    api_rules = load_api_rules(args.api_rules)
    mitre_map = load_mitre_mapping(args.mitre_rules)
    protector_sigs = load_protector_signatures(args.protector_rules)
    yara_dir = args.yara_rules or default_yara_rules_dir()
    return AnalysisBundle(path, api_rules, mitre_map, protector_sigs, yara_dir)


# ====================
#  DISPLAY FUNCTIONS
# ====================
def display_executive_summary(summary):
    ui.print_header("EXECUTIVE SUMMARY")
    ui.kv("SHA-256", summary['sha256'])
    ui.kv("MD5", summary['md5'])
    ui.kv("Imphash", summary['imphash'] or 'n/a (pefile build lacks get_imphash)')
    ui.kv("RichHash", summary['rich_hash'] or 'n/a (no Rich Header present)')
    ui.kv("Avg entropy", f"{summary['avg_entropy']:.2f} / 8.00")
    print()
    stage_sev = ['safe', 'safe', 'warning', 'critical', 'critical'][
        min(4, max(0, round(summary['difficulty_score'] / 2)))]
    ui.sev_line(stage_sev, f"Verdict: {summary['difficulty_label']} ({summary['difficulty_score']:.1f}/10.0)")
    print(f"\n  {ui.DIM_LABEL}Top threat signals{RESET}")
    ui.tree(summary['top_threats'])


def display_imports(pe_structure):
    imports = pe_structure.analyze_imports()
    ui.print_header("SUSPICIOUS IMPORTS")
    ui.print_note("API calls the binary imports, bucketed by capability. One suspicious import "
                  "alone rarely proves malice -- look for combinations (see Behavior Pattern Analysis).")
    if not imports:
        ui.sev_line('safe', "No suspicious imports found in any tracked category.")
        return
    for category, apis in imports.items():
        w = pe_structure.category_weight(category)
        sev = 'critical' if w >= 1.1 else ('warning' if w >= 0.7 else 'info')
        ui.sev_line(sev, f"[{category}]")
        ui.tree(apis, indent='      ')
        print()


def display_entropy(sections):
    ui.print_header("ENTROPY ANALYSIS")
    ui.print_note("How random each section's bytes are, 0-8 scale. Ordinary compiled code sits "
                  "~6.0-6.5. Resource sections (.rsrc) naturally run high from compressed icons -- "
                  "that's expected, not flagged the same way.")
    if not sections:
        ui.sev_line('info', "No sections found.")
        return
    name_width = max((len(s) for s in sections), default=8) + 2
    for name, entropy in sections.items():
        is_resource = name in ('.rsrc', '.reloc')
        if entropy > 7.6:
            sev = 'critical'
        elif entropy > 7.2 and not is_resource:
            sev = 'warning'
        else:
            sev = 'safe'
        bar = ui.gauge_bar(entropy / 8.0, width=30)
        print(f"  {ui.DIM_LABEL}{name.ljust(name_width)}{RESET}{bar} {ui.BRIGHT_WHITE}{entropy:4.2f}/8.00{RESET}")


def display_antidebug(has_antidebug, apis):
    ui.print_header("ANTI-DEBUG DETECTION")
    ui.print_note("API calls commonly used to detect or defeat debuggers.")
    if has_antidebug:
        ui.sev_line('warning', f"Anti-debug techniques detected: {', '.join(apis)}")
    else:
        ui.sev_line('safe', "No anti-debug APIs detected.")


def display_crypto(crypto):
    ui.print_header("CRYPTOGRAPHY DETECTION")
    ui.print_note("Windows CryptoAPI/CNG/OpenSSL usage. Extremely common in benign software -- "
                  "only meaningful combined with other signals.")
    if crypto['detected_apis']:
        ui.sev_line('warning', f"Cryptographic API usage detected: {', '.join(crypto['detected_apis'])}")
    else:
        ui.sev_line('safe', "No crypto library APIs detected.")


def display_cipher(cipher):
    ui.print_header("CIPHER / OBFUSCATION DETECTION")
    ui.print_note("Brute-force check for string obfuscation: single-byte XOR/ADD/SUB/ROL/ROR/NOT, "
                  "repeating-key XOR, and Base64.")
    if not cipher:
        ui.sev_line('safe', "No obfuscation operation matched the extracted strings.")
        return
    for op, candidates in cipher.items():
        best_key, best_count = max(candidates.items(), key=lambda kv: kv[1])
        if op == 'BASE64':
            ui.sev_line('warning', f"Base64-encoded strings -- {best_count} decode to plausible text/binary")
            continue
        if op == 'XOR (multi-byte)':
            ui.sev_line('warning', f"Repeating-key XOR, key 0x{best_key.hex()} ({len(best_key)} bytes) "
                                    f"-- {best_count} strings decode cleanly")
        elif op.startswith('NOT'):
            ui.sev_line('warning', f"{op} -- {best_count} strings decode cleanly")
        elif op.startswith('ROL') or op.startswith('ROR'):
            ui.sev_line('warning', f"{op}, shift {best_key} -- {best_count} strings decode cleanly")
        else:
            ui.sev_line('warning', f"{op} obfuscation, key 0x{best_key:02x} -- {best_count} strings decode cleanly")


def display_decoded_strings(result):
    ui.print_header("DECODED / INTERESTING STRINGS")
    if not result['strings']:
        ui.sev_line('safe', "Nothing interesting found.")
        return
    if result['op'] == 'BASE64':
        print("  Base64-decoded strings from the binary:\n")
    elif result['op']:
        key = result['key']
        key_repr = f"0x{key.hex()} ({len(key)}-byte)" if isinstance(key, bytes) else (
            f"0x{key:02x}" if isinstance(key, int) else key)
        print(f"  Applying {result['op']} (key {key_repr}):\n")
    else:
        print("  No obfuscation detected -- notable plaintext strings:\n")
    for s in result['strings']:
        print(f"    {s}")


def display_behavior_patterns(patterns):
    ui.print_header("BEHAVIOR PATTERN ANALYSIS")
    ui.print_note("Raw imports clustered into recognizable attack patterns, mapped to MITRE ATT&CK "
                  "where applicable. Each requires a COMBINATION of signals.")
    if not patterns:
        ui.sev_line('safe', "No combined attack patterns matched.")
        return
    for name, info in patterns.items():
        attck = f"  ({info['attck']})" if info.get('attck') else ""
        ui.sev_line('critical', f"{name}{attck}")
        print(f"      {info['description']}")
        ui.tree(info['evidence'], indent='      ')
        print()


def display_section_anomalies(anomalies):
    ui.print_header("SECTION ANOMALIES")
    ui.print_note("Structural red flags in the PE section table itself -- often say more than "
                  "imports do, since a packer can hide imports but rarely hides its own structure.")
    if not anomalies:
        ui.sev_line('safe', "No structural anomalies detected.")
        return
    for a in anomalies:
        label = a['section'] if a['section'] else '(unnamed)'
        ui.sev_line(a['severity'], f"[{label}] {a['issue']}")


def display_tls(has_tls, callbacks):
    ui.print_header("TLS CALLBACK DETECTION")
    ui.print_note("TLS callbacks run BEFORE the normal entry point -- before a debugger's "
                  "break-on-entry would ever fire.")
    if has_tls:
        ui.sev_line('warning', f"{len(callbacks)} TLS callback(s) found")
        ui.tree([f"0x{a:x}" for a in callbacks])
    else:
        ui.sev_line('safe', "No TLS callbacks found.")


def display_overlay(has_overlay, size, entropy, likely_signature):
    ui.print_header("OVERLAY DATA ANALYSIS")
    ui.print_note("Data appended after the last section -- invisible to section-based entropy "
                  "checks. Authenticode signatures live here too and are excluded from scoring.")
    if not has_overlay:
        ui.sev_line('safe', "No overlay data -- file size matches the section table exactly.")
        return
    if likely_signature:
        ui.sev_line('safe', f"{size:,} bytes of overlay -- matches the Authenticode signature "
                             f"directory, not a hidden payload.")
    elif entropy > 7.2 and size > 100 * 1024:
        ui.sev_line('critical', f"{size:,} bytes, entropy {entropy:.2f}/8.00 -- large and "
                                 f"high-entropy, plausibly a second-stage payload.")
    else:
        ui.sev_line('warning', f"{size:,} bytes, entropy {entropy:.2f}/8.00 -- unexplained overlay data.")


def display_import_evasion(result):
    ui.print_header("IMPORT TABLE EVASION CHECK")
    ui.print_note("A starved import table on a large binary suggests dynamic API resolution, "
                  "specifically to defeat static import scanning.")
    ui.kv("Total imported functions", result['total_imports'])
    ui.kv("Executable code size", f"{result['code_size']:,} bytes")
    ui.kv("Imports LoadLibrary/GetProcAddress", 'yes' if result['dynamic_resolvers_present'] else 'no')
    if result.get('is_dotnet'):
        ui.sev_line('info', ".NET assembly -- minimal native imports are expected, not evaluated for evasion.")
    if result['suspicious']:
        reason = "empty import table" if result['total_imports'] == 0 else "thin table + LoadLibrary/GetProcAddress"
        ui.sev_line('critical', f"Suspicious for this much code ({reason}).")
    else:
        ui.sev_line('safe', "Import table size looks proportionate to code size.")


def display_protectors(findings):
    ui.print_header("KNOWN PACKER / PROTECTOR SIGNATURE SCAN")
    ui.print_note("Section names, import DLLs, embedded strings, entry-point signatures, and "
                  "(if configured) YARA rules.")
    if not findings:
        ui.sev_line('safe', "No known packer/protector signatures matched.")
        return
    sev_map = {'HIGH': 'critical', 'MEDIUM': 'warning', 'LOW': 'info'}
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    for name, info in sorted(findings.items(), key=lambda kv: order[kv[1]['confidence']]):
        ui.sev_line(sev_map[info['confidence']], f"{name} -- confidence: {info['confidence']}")
        ui.tree(info['evidence'][:4], indent='      ')
        print()


def display_embedded_binaries(found):
    ui.print_header("EMBEDDED BINARY SCAN")
    ui.print_note("MZ/PE signatures found inside section data at offsets other than the file's "
                  "own start -- a common sign of a dropper or packer carrying a payload.")
    if not found:
        ui.sev_line('safe', "No embedded MZ/PE signatures found.")
        return
    for i, hit in enumerate(found, 1):
        ui.sev_line('warning', f"[{i}] Possible embedded PE in {hit['section']} @ offset "
                                f"0x{hit['offset']:x} (~{hit['size_hint']} bytes to end of section)")


def display_risk_factors(breakdown, top_n=3):
    if not breakdown:
        return
    print(f"\n  {ui.DIM_LABEL}Why this score{RESET}")
    top = sorted(breakdown, key=lambda d: -d['value'])[:top_n]
    for i, b in enumerate(top):
        branch = '\u2514\u2500\u2500' if i == len(top) - 1 else '\u251c\u2500\u2500'
        color = ui.severity_color(b['severity'])
        print(f"    {ui.DIM_LABEL}{branch}{RESET} {color}{b['reason']}{RESET}  "
              f"{ui.DIM_LABEL}(+{b['value']:.2f}){RESET}")


def display_difficulty(result, bundle):
    ui.print_header("REVERSE-ENGINEERING DIFFICULTY")
    stage = result['stage']
    sev = ['safe', 'safe', 'warning', 'critical', 'critical'][stage]
    color = ui.severity_color(sev)
    bar = ui.gauge_bar(result['score'] / 10.0, width=30)
    print(f"\n  {bar} {ui.BRIGHT_WHITE}{result['score']:.1f}/10.0{RESET}")
    ui.typewriter(f"  Verdict: {result['label']}", delay=0.008, color=color)
    print(f"  \"{result['quote']}\"")
    display_risk_factors(result['breakdown'])

    approach, reasoning = bundle.scorer.suggest_approach()
    ui.print_header("SUGGESTED APPROACH: STATIC vs DYNAMIC")
    print(f"  -> {approach}\n")
    for line in reasoning:
        ui.print_note(line)

    ui.section_divider()
    display_correlated_findings(bundle.scorer.correlate())


def display_correlated_findings(findings):
    ui.print_header("CORRELATED FINDINGS")
    ui.print_note("Individual sections cross-checked against each other instead of read in "
                  "isolation -- a single anti-debug import means little; found together with "
                  "other signals it means something.")
    for f in findings:
        ui.sev_line(f['severity'], f['text'])
        print()


# ============================================================
#  FULL ANALYSIS ORCHESTRATION
# ============================================================
def run_full_analysis(bundle, html_path=None, pace=True):
    def progress(current, total, label):
        ui.show_progress_bar(current, total, label)
    bundle.set_progress_callback(progress)

    difficulty = bundle.scorer.calculate()
    executive = ExecutiveSummary(bundle.pe_structure, bundle.protectors, bundle.behavior, difficulty).build()
    display_executive_summary(executive)
    ui.section_divider(pause=ui.SECTION_PAUSE if pace else 0)

    steps = [
        ("Scanning import table", lambda: display_imports(bundle.pe_structure)),
        ("Calculating section entropy", lambda: display_entropy(bundle.pe_structure.analyze_sections())),
        ("Checking for anti-debug tricks", lambda: display_antidebug(*bundle.pe_structure.detect_antidebug())),
        ("Checking for crypto APIs", lambda: display_crypto(bundle.pe_structure.detect_crypto_apis())),
        ("Detecting obfuscation patterns", lambda: display_cipher(bundle.obfuscation.detect_cipher_operations(progress))),
        ("Decoding interesting strings", lambda: display_decoded_strings(bundle.obfuscation.decode_strings_preview())),
        ("Clustering behavior patterns", lambda: display_behavior_patterns(bundle.behavior.detect_patterns())),
        ("Scanning section anatomy", lambda: display_section_anomalies(bundle.pe_structure.analyze_section_anatomy())),
        ("Checking for TLS callbacks", lambda: display_tls(*bundle.pe_structure.detect_tls_callbacks())),
        ("Checking for overlay data", lambda: display_overlay(*bundle.pe_structure.detect_overlay())),
        ("Checking import table for evasion", lambda: display_import_evasion(bundle.pe_structure.detect_import_evasion())),
        ("Matching known packer/protector signatures", lambda: display_protectors(bundle.protectors.detect())),
        ("Scanning for embedded binaries", lambda: display_embedded_binaries(bundle.pe_structure.scan_embedded_binaries())),
    ]
    for label, fn in steps:
        ui.fake_loading(label, 0.4 if pace else 0)
        fn()
        ui.section_divider(pause=ui.SECTION_PAUSE if pace else 0)

    ui.fake_loading("Calculating difficulty score", 0.6 if pace else 0)
    display_difficulty(difficulty, bundle)

    if html_path:
        anomalies = bundle.pe_structure.analyze_section_anatomy()
        report_path = generate_html_report(
            html_path, file_path=bundle.path, executive_summary=executive, difficulty_result=difficulty,
            correlated_findings=bundle.scorer.correlate(), sections=bundle.pe_structure.analyze_sections(),
            imports=bundle.pe_structure.analyze_imports(), protectors=bundle.protectors.detect(),
            behavior=bundle.behavior.detect_patterns(), section_anomalies=anomalies)
        print(f"\n  HTML report written to: {report_path}")

    return difficulty


# ============================================================
#  INTERACTIVE MENU (single-file exploratory mode)
# ============================================================
def ask_yes_no(prompt):
    while True:
        ans = input(f"{prompt} (y/n): ").strip().lower()
        if ans in ('y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False


def ask_file_path():
    print("\nReady to analyze. Drop a PE file path below ('q' to quit).")
    while True:
        path = input("> ").strip().strip('"')
        if path.lower() == 'q':
            return None
        if not os.path.exists(path):
            print("File not found. Try again.\n")
            continue
        return path


# ============================================================
#  INTERACTIVE SHELL (systorch> ...)
# ============================================================
SHELL_HELP = f"""
{ui.DIM_LABEL}Commands:{RESET}
  imports, imp            Suspicious import table
  entropy, ent            Section entropy
  antidebug, ad           Anti-debug detection
  crypto                  Cryptography API detection
  cipher, strings         Cipher/obfuscation detection + decoded strings
  behavior, beh           Behavior pattern analysis (MITRE ATT&CK)
  sections, anomalies     Section anomaly scan
  tls                     TLS callback detection
  overlay, ov             Overlay data analysis
  evasion                 Import table evasion check
  protectors, packers     Known packer/protector signatures
  embedded, emb           Embedded binary scan
  score, difficulty       Difficulty score + approach advisor + correlation
  summary, dashboard      Executive summary
  full, all               Run the complete analysis, section by section
  compare <file>          Compare difficulty against another file
  html [path]             Export an HTML report
  load <file>             Load a different file into this session
  help, ?                 This message
  exit, quit, q           Leave the shell
"""

_SHELL_ALIASES = {
    'imp': 'imports', 'ent': 'entropy', 'ad': 'antidebug', 'strings': 'cipher',
    'beh': 'behavior', 'sections': 'anomalies', 'sec': 'anomalies', 'ov': 'overlay',
    'packers': 'protectors', 'pkr': 'protectors', 'emb': 'embedded',
    'difficulty': 'score', 'diff': 'score', 'dashboard': 'dash', 'all': 'full',
    'open': 'load', '?': 'help', 'quit': 'exit', 'q': 'exit',
}


def _shell_embedded(bundle, args):
    found = bundle.pe_structure.scan_embedded_binaries()
    display_embedded_binaries(found)
    if found and ask_yes_no("\nRun a quick sub-analysis on the first embedded binary found?"):
        hit = found[0]
        data = bundle.pe_structure.get_embedded_binary_bytes(hit['section'], hit['offset'])
        if data:
            tmp = tempfile.NamedTemporaryFile(suffix='.exe', delete=False)
            try:
                tmp.write(data)
                tmp.close()
                try:
                    sub_bundle = load_bundle(tmp.name, args)
                    sub_result = sub_bundle.scorer.calculate()
                    ui.print_header("EMBEDDED BINARY -- QUICK VERDICT")
                    display_risk_factors(sub_result['breakdown'])
                    print(f"  Verdict: {sub_result['label']} ({sub_result['score']:.1f}/10.0)")
                except (FileNotFoundError, ValueError) as e:
                    print(f"Could not parse the extracted bytes as a valid PE: {e}")
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass


def _shell_compare(bundle, args, rest):
    second_path = rest or ask_file_path()
    if not second_path:
        return
    try:
        second_bundle = load_bundle(second_path, args)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error loading second file: {e}")
        return
    r1 = bundle.scorer.calculate()
    r2 = second_bundle.scorer.calculate()
    ui.print_header("COMPARISON")
    ui.kv("A", f"{r1['score']:.1f}/10.0 -- {r1['label']}")
    ui.kv("B", f"{r2['score']:.1f}/10.0 -- {r2['label']}")


def _shell_html(bundle, rest):
    path = rest.strip() or (os.path.splitext(bundle.path)[0] + ".systorch.html")
    run_full_analysis(bundle, html_path=path, pace=False)


def _shell_load(args, rest):
    path = rest.strip().strip('"') or ask_file_path()
    if not path:
        return None
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return None
    try:
        return load_bundle(path, args)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        return None


def run_shell(bundle, args):
    """radare2/msfconsole-style command prompt, replacing the old
    18-item numbered menu that filled the scrollback on every visit."""
    print(f"\n{ui.DIM_LABEL}Loaded:{RESET} {ui.BRIGHT_WHITE}{os.path.basename(bundle.path)}{RESET}   "
          f"{ui.DIM_LABEL}(type 'help' for commands){RESET}")
    while True:
        prompt = f"{ui.BOLD_GREEN}systorch{RESET}{ui.DIM_LABEL}({os.path.basename(bundle.path)}){RESET}> "
        try:
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = _SHELL_ALIASES.get(parts[0].lower(), parts[0].lower())
        rest = parts[1].strip() if len(parts) > 1 else ''

        if cmd == 'exit':
            return
        elif cmd == 'help':
            print(SHELL_HELP)
        elif cmd == 'imports':
            display_imports(bundle.pe_structure)
        elif cmd == 'entropy':
            display_entropy(bundle.pe_structure.analyze_sections())
        elif cmd == 'antidebug':
            display_antidebug(*bundle.pe_structure.detect_antidebug())
        elif cmd == 'crypto':
            display_crypto(bundle.pe_structure.detect_crypto_apis())
        elif cmd == 'cipher':
            display_cipher(bundle.obfuscation.detect_cipher_operations())
            display_decoded_strings(bundle.obfuscation.decode_strings_preview())
        elif cmd == 'behavior':
            display_behavior_patterns(bundle.behavior.detect_patterns())
        elif cmd == 'anomalies':
            display_section_anomalies(bundle.pe_structure.analyze_section_anatomy())
        elif cmd == 'tls':
            display_tls(*bundle.pe_structure.detect_tls_callbacks())
        elif cmd == 'overlay':
            display_overlay(*bundle.pe_structure.detect_overlay())
        elif cmd == 'evasion':
            display_import_evasion(bundle.pe_structure.detect_import_evasion())
        elif cmd == 'protectors':
            display_protectors(bundle.protectors.detect())
        elif cmd == 'embedded':
            _shell_embedded(bundle, args)
        elif cmd == 'score':
            display_difficulty(bundle.scorer.calculate(), bundle)
        elif cmd == 'dash':
            result = bundle.scorer.calculate()
            executive = ExecutiveSummary(bundle.pe_structure, bundle.protectors, bundle.behavior, result).build()
            display_executive_summary(executive)
        elif cmd == 'full':
            run_full_analysis(bundle, pace=not args.fast)
        elif cmd == 'compare':
            _shell_compare(bundle, args, rest)
        elif cmd == 'html':
            _shell_html(bundle, rest)
        elif cmd == 'load':
            new_bundle = _shell_load(args, rest)
            if new_bundle is not None:
                bundle = new_bundle
        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for the command list.")


def interactive_loop(args):
    """No file argument (e.g. double-clicking the packaged .exe): boot
    sequence, prompt for a file, quick dashboard, then the shell."""
    ui.welcome_screen()
    path = ask_file_path()
    if path is None:
        ui.goodbye()
        return
    try:
        bundle = load_bundle(path, args)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        ui.goodbye()
        return
    result = bundle.scorer.calculate()
    executive = ExecutiveSummary(bundle.pe_structure, bundle.protectors, bundle.behavior, result).build()
    display_executive_summary(executive)
    run_shell(bundle, args)
    ui.goodbye()


# ============================================================
#  DIRECT PASS-THROUGH / BULK MODE
# ============================================================
def run_direct(paths, args):
    """
    File argument(s) given on the command line -- e.g. dragging a binary
    onto the packaged .exe in Explorer, or `systorch sample.exe`.

    A single file in a real (interactive) terminal skips the boot
    sequence and menu entirely, renders the dashboard immediately, and
    drops into the shell already loaded -- the "single-pass dashboard"
    behavior. Multiple files, or output that isn't a live terminal
    (piped/redirected -- the actual scripted-batch case), get the full
    section-by-section report per file with no blocking prompts, since
    a shell prompt would just hang a script.
    """
    exit_code = 0
    single_interactive = len(paths) == 1 and sys.stdin.isatty() and not args.quiet

    for i, path in enumerate(paths, 1):
        if len(paths) > 1:
            ui.print_batch_banner(i, len(paths), path)
        try:
            bundle = load_bundle(path, args)
        except FileNotFoundError:
            print(f"File not found: {path}")
            exit_code = 1
            continue
        except ValueError as e:
            print(f"Error: {e}")
            exit_code = 1
            continue

        if single_interactive:
            result = bundle.scorer.calculate()
            executive = ExecutiveSummary(bundle.pe_structure, bundle.protectors, bundle.behavior, result).build()
            display_executive_summary(executive)
            print(f"\n  {ui.DIM_LABEL}Type 'full' for the complete breakdown, or 'help' for all commands.{RESET}")
            run_shell(bundle, args)
            ui.goodbye()
        else:
            html_path = None
            if args.html:
                html_path = args.html if len(paths) == 1 else os.path.splitext(path)[0] + ".systorch.html"
            run_full_analysis(bundle, html_path=html_path, pace=not args.fast)

    return exit_code


# ============================================================
#  ARGPARSE / MAIN
# ============================================================
def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="systorch",
        description="Static Analysis & Reverse Engineering Difficulty Estimator")
    p.add_argument("files", nargs="*", help="PE file(s) to analyze. Omit for interactive mode.")
    p.add_argument("--fast", action="store_true", help="Disable artificial delays (typewriter/loading bars).")
    p.add_argument("--quiet", action="store_true", help="Also skip ASCII art/boot sequence -- plain, script-friendly output.")
    p.add_argument("--debug", action="store_true", help="Show full tracebacks for internal parsing exceptions.")
    p.add_argument("--html", metavar="PATH", help="Write an HTML report. With multiple files, used as a suffix pattern per file.")
    p.add_argument("--yara-rules", metavar="DIR", help="Directory of .yar/.yara files (requires yara-python).")
    p.add_argument("--api-rules", metavar="PATH", help="Override path to apis.json.")
    p.add_argument("--mitre-rules", metavar="PATH", help="Override path to mitre_mapping.json.")
    p.add_argument("--protector-rules", metavar="PATH", help="Override path to protector_signatures.json.")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    configure_logging(debug=args.debug)
    ui.configure(fast=args.fast, quiet=args.quiet)

    if args.files:
        expanded = []
        for pattern in args.files:
            matches = glob.glob(pattern)
            expanded.extend(matches if matches else [pattern])
        return run_direct(expanded, args)

    try:
        interactive_loop(args)
    except KeyboardInterrupt:
        print()
        ui.goodbye()
    return 0


if __name__ == "__main__":
    sys.exit(main())
