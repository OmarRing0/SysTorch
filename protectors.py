"""
ProtectorSignatureAnalyzer: known packer/protector identification.
 a rules directory is supplied (via --yara-rules), every .yar/.yara file in that
"""

import glob
import os

from .logutil import logger, PARSE_EXCEPTIONS
from .pe_structure import PEStructureAnalyzer

_CONF_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}


class ProtectorSignatureAnalyzer:
    def __init__(self, pe, signatures, yara_rules_dir=None):
        self.pe = pe
        self.signatures = signatures or {}
        self.yara_rules_dir = yara_rules_dir
        self._cache = None
        self._yara_rules = None
        self._yara_load_attempted = False

    def _add(self, findings, name, confidence, evidence):
        existing = findings.get(name)
        if existing is None or _CONF_RANK[confidence] > _CONF_RANK[existing['confidence']]:
            findings[name] = {'confidence': confidence, 'evidence': []}
        findings[name]['evidence'].extend(e for e in evidence if e not in findings[name]['evidence'])

    def _load_yara(self):
        if self._yara_load_attempted:
            return
        self._yara_load_attempted = True
        if not self.yara_rules_dir:
            return
        try:
            import yara
        except ImportError:
            logger.info("yara-python not installed -- skipping YARA scan "
                        "(pip install yara-python to enable --yara-rules)")
            return
        rule_files = {}
        for i, path in enumerate(sorted(
                glob.glob(os.path.join(self.yara_rules_dir, '*.yar')) +
                glob.glob(os.path.join(self.yara_rules_dir, '*.yara')))):
            rule_files[f"ns{i}"] = path
        if not rule_files:
            logger.warning("No .yar/.yara files found in %s", self.yara_rules_dir)
            return
        try:
            self._yara_rules = yara.compile(filepaths=rule_files)
        except Exception as e:
            logger.warning("Failed to compile YARA rules from %s: %s", self.yara_rules_dir, e)
            self._yara_rules = None

    def _scan_yara(self, findings):
        self._load_yara()
        if self._yara_rules is None:
            return
        try:
            matches = self._yara_rules.match(data=self.pe.__data__)
        except Exception as e:
            logger.debug("YARA match failed: %s", e, exc_info=True)
            return
        for m in matches:
            meta = getattr(m, 'meta', {}) or {}
            confidence = str(meta.get('confidence', 'MEDIUM')).upper()
            if confidence not in _CONF_RANK:
                confidence = 'MEDIUM'
            name = meta.get('description', m.rule)
            self._add(findings, name, confidence, [f"YARA rule matched: {m.rule}"])

    def detect(self):
        if self._cache is not None:
            return self._cache
        findings = {}

        try:
            section_names = [s.Name.decode('utf-8', errors='ignore').strip('\x00') for s in self.pe.sections]
        except PARSE_EXCEPTIONS:
            section_names = []
        for protector, sigs in self.signatures.get('section_names', {}).items():
            hits = [n for n in section_names if n in sigs]
            if hits:
                self._add(findings, protector, 'HIGH', [f"section name(s): {', '.join(hits)}"])

        try:
            dll_names_lower = [
                (e.dll.decode('utf-8', errors='ignore') if e.dll else '').lower()
                for e in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', [])
            ]
        except PARSE_EXCEPTIONS:
            dll_names_lower = []
        for protector, dlls in self.signatures.get('import_dlls', {}).items():
            hits = [d for d in dll_names_lower if d in dlls]
            if hits:
                self._add(findings, protector, 'HIGH', [f"import DLL: {', '.join(hits)}"])

        try:
            blob = b' '.join(s.get_data() for s in self.pe.sections).lower()
        except PARSE_EXCEPTIONS:
            blob = b''
        for protector, needles in self.signatures.get('string_markers', {}).items():
            hits = [n for n in needles if n.encode() in blob]
            if hits:
                confidence = 'HIGH' if protector in findings and findings[protector]['confidence'] == 'HIGH' else 'MEDIUM'
                self._add(findings, protector, confidence, [f"embedded string: '{h}'" for h in hits])

        try:
            if hasattr(self.pe, 'FileInfo'):
                for fi_list in self.pe.FileInfo:
                    for fi in fi_list:
                        if fi.Key == b'StringFileInfo':
                            for st in fi.StringTable:
                                for k, v in st.entries.items():
                                    val = (v or b'').lower() if isinstance(v, bytes) else str(v).lower().encode()
                                    for protector, needles in self.signatures.get('string_markers', {}).items():
                                        for needle in needles:
                                            if needle.encode() in val:
                                                self._add(findings, protector, 'MEDIUM',
                                                           [f"version info {k.decode(errors='ignore')}: matches '{needle}'"])
        except PARSE_EXCEPTIONS:
            pass

        for sig in self.signatures.get('entry_point_signatures', []):
            try:
                ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                needle = bytes.fromhex(sig['bytes_hex'])
                ep_bytes = self.pe.get_data(ep_rva, len(needle))
                if ep_bytes == needle:
                    self._add(findings, sig['name'], sig.get('confidence', 'MEDIUM'), [sig.get('note', 'entry-point byte match')])
            except PARSE_EXCEPTIONS:
                pass

        if not findings:
            try:
                ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                ep_section = None
                for section in self.pe.sections:
                    start = section.VirtualAddress
                    end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
                    if start <= ep_rva < end:
                        ep_section = section
                        break
                if ep_section is not None:
                    name = ep_section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    entropy = PEStructureAnalyzer.calculate_entropy(ep_section.get_data())
                    if entropy > 7.5:
                        self._add(findings, 'Unknown/Generic packer', 'LOW',
                                   [f"entry point lies in section '{name}' with entropy {entropy:.2f}/8.00 "
                                    f"-- consistent with a packer stub, but no specific family signature matched"])
            except PARSE_EXCEPTIONS:
                pass

        self._scan_yara(findings)

        self._cache = findings
        return findings
