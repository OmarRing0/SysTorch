"""
DifficultyScorer: combines PEStructureAnalyzer, ObfuscationAnalyzer,
ProtectorSignatureAnalyzer, and BehaviorAnalyzer into a single difficulty
score/verdict, a static-vs-dynamic approach recommendation, and a
cross-signal correlation pass.

Deliberately returns plain data (dicts/lists), not printed output --
display is ui.py/cli.py's job, not this module's. That separation is
what makes each piece testable on its own instead of only being
verifiable by eyeballing terminal output.

Every finding carries a `severity` of 'critical' / 'warning' / 'info' /
'safe' so the display layer can apply real traffic-light coloring instead
of making everything the same color.
"""

import math

DIFFICULTY_LABELS = [
    "TRIVIAL  -  Script Kiddie Bait",
    "EASY     -  Weekend Project",
    "MODERATE -  Requires Coffee",
    "HARD     -  Bring Ghidra & Patience",
    "NIGHTMARE - Expert Only",
]

STAGE_QUOTES = [
    "strings(1) and a cup of coffee will get you most of the way there.",
    "A weekend, a disassembler, and mild curiosity is all this takes.",
    "Bring a real toolkit. This one wants your attention, not your fear.",
    "Bring backups, bring patience -- this one bites back.",
    "Abandon hope, all ye who enter here. Bring Ghidra, snacks, and a friend.",
]

_CATEGORY_WEIGHT_SEVERITY = [
    (1.1, 'critical'),
    (0.7, 'warning'),
    (0.0, 'info'),
]


def _severity_for_weight(weight):
    for threshold, sev in _CATEGORY_WEIGHT_SEVERITY:
        if weight >= threshold:
            return sev
    return 'info'


class DifficultyScorer:
    def __init__(self, pe_structure, obfuscation, protectors, behavior, progress_cb=None):
        self.pe = pe_structure
        self.obf = obfuscation
        self.prot = protectors
        self.beh = behavior
        self.progress_cb = progress_cb

    # ---------------- main score ----------------
    def calculate(self):
        imports = self.pe.analyze_imports()
        sections = self.pe.analyze_sections()
        has_antidebug, ad_apis = self.pe.detect_antidebug()
        crypto = self.pe.detect_crypto_apis()
        cipher = self.obf.detect_cipher_operations(show_progress=self.progress_cb)
        has_tls, tls_callbacks = self.pe.detect_tls_callbacks()
        has_overlay, overlay_size, overlay_entropy, likely_signature = self.pe.detect_overlay()
        import_evasion = self.pe.detect_import_evasion()
        protectors = self.prot.detect()

        score = 0.0
        breakdown = []  # list of {'value', 'reason', 'severity'}

        def summarize(apis, limit=3):
            apis = list(apis)
            shown = ', '.join(apis[:limit])
            if len(apis) > limit:
                shown += ', ...'
            return shown

        def add(value, reason, severity):
            breakdown.append({'value': value, 'reason': reason, 'severity': severity})

        import_score = 0.0
        for cat, apis in imports.items():
            w = self.pe.category_weight(cat)
            n = len(apis)
            contribution = w * (1.0 + 0.25 * math.log2(n)) if n > 1 else w
            contribution = min(contribution, w * 1.8)
            import_score += contribution
            add(contribution, f"{cat} API usage ({summarize(apis)})", _severity_for_weight(w))
        score += min(import_score, 5.5)

        if has_antidebug:
            c = 0.8 + min(0.15 * len(ad_apis), 0.7)
            score += c
            add(c, f"Anti-debugging techniques detected ({summarize(ad_apis)})", 'warning')

        if crypto['detected_apis']:
            score += 0.8
            add(0.8, f"Cryptographic API usage ({summarize(crypto['detected_apis'])})", 'warning')

        if cipher:
            c = min(0.8 * len(cipher), 2.0)
            score += c
            add(c, f"String obfuscation detected ({', '.join(cipher.keys())})", 'warning')

        entropy_exempt = {'.rsrc', '.reloc'}
        packed_sections = []
        for name, e in sections.items():
            if name in entropy_exempt:
                if e > 7.6:
                    packed_sections.append(name)
            elif e > 7.2:
                packed_sections.append(name)
        if packed_sections:
            c = min(len(packed_sections) * 0.6, 1.8)
            score += c
            sev = 'critical' if any(sections[n] > 7.6 for n in packed_sections) else 'warning'
            add(c, f"{len(packed_sections)} section(s) with packer/encryption-level entropy "
                   f"({summarize(packed_sections)})", sev)

        if has_tls:
            c = 1.2 + min(0.2 * len(tls_callbacks), 0.6)
            score += c
            add(c, f"{len(tls_callbacks)} TLS callback(s) -- code executes before the normal entry point", 'warning')

        if has_overlay and not likely_signature:
            size_factor = min(overlay_size / (512 * 1024), 1.0)
            entropy_factor = max(0.0, (overlay_entropy - 6.5) / 1.5)
            c = min(0.4 + 1.6 * size_factor * max(entropy_factor, 0.3), 2.0)
            score += c
            add(c, f"{overlay_size:,} bytes of overlay data past the last section "
                   f"(entropy {overlay_entropy:.2f}/8.00)", 'warning')
        elif has_overlay and likely_signature:
            add(0.0, f"{overlay_size:,} bytes of overlay data, but it matches the Authenticode "
                     f"signature directory -- not counted as suspicious", 'safe')

        if import_evasion['suspicious']:
            score += 1.5
            add(1.5, f"Import table has only {import_evasion['total_imports']} functions across "
                     f"{import_evasion['code_size']:,} bytes of executable code -- likely resolves "
                     f"APIs dynamically to evade static import scanning", 'critical')

        protector_weight = {'HIGH': 2.2, 'MEDIUM': 1.2, 'LOW': 0.5}
        protector_severity = {'HIGH': 'critical', 'MEDIUM': 'warning', 'LOW': 'info'}
        if protectors:
            c = 0.0
            names = []
            worst_sev = 'info'
            for name, info in protectors.items():
                c += protector_weight[info['confidence']]
                names.append(f"{name} ({info['confidence']})")
                if protector_severity[info['confidence']] == 'critical':
                    worst_sev = 'critical'
                elif protector_severity[info['confidence']] == 'warning' and worst_sev != 'critical':
                    worst_sev = 'warning'
            c = min(c, 3.5)
            score += c
            add(c, f"Known packer/protector signature(s): {', '.join(names)}", worst_sev)

        section_anomalies = self.pe.analyze_section_anatomy()
        for a in section_anomalies:
            add(0.3 if a['severity'] == 'critical' else 0.1, f"Section anomaly: {a['issue']}", a['severity'])
            if a['severity'] == 'critical':
                score += 0.3
            elif a['severity'] == 'warning':
                score += 0.1

        score = min(score, 10.0)
        breakdown.sort(key=lambda d: d['value'], reverse=True)

        if score < 2.5:
            stage = 0
        elif score < 4.5:
            stage = 1
        elif score < 6.5:
            stage = 2
        elif score < 8.5:
            stage = 3
        else:
            stage = 4

        high_conf_protector = any(i['confidence'] == 'HIGH' for i in protectors.values())
        medium_plus_protector = any(i['confidence'] in ('HIGH', 'MEDIUM') for i in protectors.values())
        floor_stage, floor_reason = 0, None
        if high_conf_protector and has_tls:
            floor_stage, floor_reason = 4, "HIGH-confidence protector signature + TLS callbacks"
        elif high_conf_protector:
            floor_stage, floor_reason = 3, "HIGH-confidence protector signature match"
        elif has_tls and has_antidebug and import_evasion['suspicious']:
            floor_stage, floor_reason = 3, "TLS callbacks + anti-debug + import-table evasion together"
        elif medium_plus_protector and has_tls:
            floor_stage, floor_reason = 3, "MEDIUM+ confidence protector signature + TLS callbacks"

        if floor_stage > stage:
            stage = floor_stage
            add(0.0, f"Difficulty floor applied -- {floor_reason} (raw score alone would have "
                     f"under-stated this)", 'critical')

        return {
            'score': score,
            'label': DIFFICULTY_LABELS[stage],
            'stage': stage,
            'quote': STAGE_QUOTES[stage],
            'breakdown': breakdown,
        }

    # ---------------- static vs dynamic approach ----------------
    def suggest_approach(self):
        has_antidebug, ad_apis = self.pe.detect_antidebug()
        sections = self.pe.analyze_sections()
        cipher = self.obf.detect_cipher_operations()
        packed_sections = [n for n, e in sections.items() if e > 7.2 and n not in ('.rsrc', '.reloc')]
        anomalies = self.pe.analyze_section_anatomy()
        rwx = any('RWX' in a['issue'] or 'executable' in a['issue'] for a in anomalies)
        embedded = self.pe.scan_embedded_binaries()
        has_tls, tls_callbacks = self.pe.detect_tls_callbacks()
        protectors = self.prot.detect()
        import_evasion = self.pe.detect_import_evasion()

        packed_or_obfuscated = bool(packed_sections) or bool(cipher) or rwx or bool(protectors)
        packed_or_obfuscated = packed_or_obfuscated or has_tls or import_evasion['suspicious']

        if packed_or_obfuscated and has_antidebug:
            approach = "MIXED -- lean dynamic, but start static"
            reasoning = [
                "Packed/obfuscated sections and anti-debug checks were both found. Static analysis "
                "on the packed form will show you little beyond the loader stub, and a naive "
                "debugger attach will likely be detected.",
                "Start static just long enough to map imports/sections and pick an unpacking "
                "strategy, then move to dynamic analysis in an isolated sandbox (with anti-anti-debug "
                "measures, or a monitoring approach like API hooking / ETW) to capture the unpacked "
                "code and runtime behavior.",
            ]
        elif packed_or_obfuscated:
            approach = "DYNAMIC-FIRST"
            reasoning = [
                "The binary looks packed/obfuscated (or shows early-execution/evasion signals) but "
                "no anti-debug checks were detected. Static analysis on the packed form won't reveal "
                "much of the real logic.",
                "Run it in an isolated sandbox/debugger to let it unpack itself, dump the unpacked "
                "memory image, then switch to static analysis on that dump.",
            ]
        elif has_antidebug:
            approach = "STATIC-FIRST"
            reasoning = [
                "Anti-debug checks were found but the binary doesn't look packed or obfuscated -- "
                "the code itself is probably readable as-is.",
                "Static analysis (disassembler/decompiler) will likely get you most of the way "
                "without ever needing to fight the anti-debug logic.",
            ]
        else:
            approach = "STATIC-FIRST"
            reasoning = [
                "No packing, no obfuscation, no anti-debug tricks, no early-execution/evasion "
                "signals. A disassembler/decompiler alone should get you a full picture quickly.",
                "Only reach for dynamic analysis if something behaves differently than the static "
                "read suggests.",
            ]

        if embedded:
            reasoning.append(f"{len(embedded)} possible embedded PE signature(s) were found -- "
                              f"extract and run this whole pipeline on those separately.")
        if has_tls:
            reasoning.append(f"{len(tls_callbacks)} TLS callback(s) run before the normal entry "
                              f"point -- set a breakpoint there too, not just main/WinMain.")
        if protectors:
            top = sorted(protectors.items(), key=lambda kv: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[kv[1]['confidence']])[0]
            reasoning.append(f"Signature match for {top[0]} ({top[1]['confidence']} confidence) -- "
                              f"look up known unpacking notes for that specific tool.")
        if import_evasion['suspicious']:
            reasoning.append("Import table looks artificially thin for the code size -- expect the "
                              "real API surface to only be visible via runtime API monitoring.")

        return approach, reasoning

    # ---------------- correlated findings ----------------
    def correlate(self):
        has_antidebug, ad_apis = self.pe.detect_antidebug()
        has_tls, tls_callbacks = self.pe.detect_tls_callbacks()
        has_overlay, overlay_size, overlay_entropy, overlay_is_signature = self.pe.detect_overlay()
        import_evasion = self.pe.detect_import_evasion()
        protectors = self.prot.detect()
        cipher = self.obf.detect_cipher_operations()
        sections = self.pe.analyze_sections()
        anomalies = self.pe.analyze_section_anatomy()
        embedded = self.pe.scan_embedded_binaries()
        behavior = self.beh.detect_patterns()

        packed_sections = [n for n, e in sections.items() if e > 7.2 and n not in ('.rsrc', '.reloc')]
        rwx = any('RWX' in a['issue'] or 'executable' in a['issue'] for a in anomalies)

        findings = []  # list of {'text', 'severity'}

        def add(text, severity):
            findings.append({'text': text, 'severity': severity})

        high_conf_protector = {n: i for n, i in protectors.items() if i['confidence'] == 'HIGH'}
        if high_conf_protector and has_tls:
            add(f"CONFIRMED evasive packing: {', '.join(high_conf_protector)} signature(s) plus TLS "
                f"callbacks means code runs, and likely checks its environment, before you ever reach "
                f"a normal breakpoint. Treat the numeric difficulty score as a floor, not a ceiling.",
                'critical')
        elif high_conf_protector:
            add(f"High-confidence protector match ({', '.join(high_conf_protector)}) -- plan your "
                f"approach around that specific tool's known unpacking method.", 'critical')

        if has_tls and has_antidebug:
            add("TLS callbacks AND anti-debug imports both present -- anti-analysis checks likely "
                "run twice: once before the entry point (TLS) and again from within main code.",
                'warning')

        if import_evasion['suspicious'] and (packed_sections or protectors):
            add("Starved import table AND packing/protector evidence together -- this is a large "
                "binary deliberately hiding its real API surface.", 'critical')
        elif import_evasion['suspicious']:
            add("Import table is suspiciously thin for the amount of code present, with no other "
                "packing evidence -- worth checking manually.", 'warning')

        if has_overlay and not overlay_is_signature and overlay_size > 200 * 1024 and overlay_entropy > 7.2 \
                and (packed_sections or embedded):
            add(f"Large, high-entropy overlay ({overlay_size:,} bytes, not explained by a digital "
                f"signature) combined with packing/embedded-binary evidence strongly suggests a "
                f"second-stage payload.", 'critical')

        if rwx and (has_antidebug or import_evasion['suspicious']):
            add("RWX section present alongside anti-analysis signals -- consistent with a "
                "self-modifying or self-unpacking stub.", 'warning')

        if behavior and cipher:
            add(f"Behavior pattern(s) matched ({', '.join(behavior.keys())}) AND string obfuscation "
                f"detected -- the decoded strings may be the config/C2/license data those behaviors "
                f"use at runtime.", 'warning')

        if not findings:
            if not (has_tls or has_overlay or protectors or import_evasion['suspicious'] or packed_sections
                    or has_antidebug or cipher or behavior):
                add("No individual signal fired, and none of the correlated combinations applied "
                    "either -- this genuinely looks like an ordinary, unprotected binary.", 'safe')
            else:
                add("Individual signals were found above, but none formed one of the stronger "
                    "correlated combinations -- treat them as independent, moderate-confidence "
                    "leads rather than a single confirmed pattern.", 'info')

        return findings
