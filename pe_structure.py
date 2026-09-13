
import hashlib
import math
from collections import Counter

import pefile

from .logutil import logger, PARSE_EXCEPTIONS

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

STANDARD_SECTION_NAMES = {
    '.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.pdata',
    '.rsrc', '.reloc', '.tls', '.debug', '.CRT', '.gfids'
}


class PEStructureAnalyzer:
    def __init__(self, pe, file_path, api_rules):
        self.pe = pe
        self.file_path = file_path
        self.api_rules = api_rules or {}

        self._sections_cache = None
        self._imports_cache = None
        self._total_import_count_cache = None
        self._antidebug_cache = None
        self._crypto_cache = None
        self._tls_cache = None
        self._overlay_cache = None
        self._import_evasion_cache = None
        self._hashes_cache = None

    # ---------------- entropy ----------------
    @staticmethod
    def calculate_entropy(data):
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
        return 0.0 if entropy == 0 else entropy  # normalizes -0.0 (a single repeated byte) to 0.0

    def analyze_sections(self):
        if self._sections_cache is not None:
            return self._sections_cache
        results = {}
        try:
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                results[name] = self.calculate_entropy(section.get_data())
        except PARSE_EXCEPTIONS as e:
            logger.debug("analyze_sections: %s", e, exc_info=True)
        self._sections_cache = results
        return results

    # ---------------- imports ----------------
    def analyze_imports(self):
        if self._imports_cache is not None:
            return self._imports_cache
        categories = self.api_rules.get('categories', {})
        # Build a flat lookup: api name -> category, once, instead of
        # scanning every category list for every import (this matters
        # once the API list is user-extended to hundreds of entries).
        api_to_category = {}
        for cat, info in categories.items():
            for api in info.get('apis', []):
                api_to_category[api] = cat

        found = {}
        try:
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    api_name = imp.name.decode('utf-8', errors='ignore')
                    cat = api_to_category.get(api_name)
                    if cat:
                        found.setdefault(cat, []).append(api_name)
        except PARSE_EXCEPTIONS as e:
            logger.debug("analyze_imports: %s", e, exc_info=True)
        self._imports_cache = found
        return found

    def category_weight(self, category):
        return self.api_rules.get('categories', {}).get(category, {}).get('weight', 0.25)

    def _total_import_count(self):
        if self._total_import_count_cache is not None:
            return self._total_import_count_cache
        total = 0
        dll_names = []
        try:
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
                total += len(entry.imports)
                dll_names.append(entry.dll.decode('utf-8', errors='ignore') if entry.dll else '')
        except PARSE_EXCEPTIONS as e:
            logger.debug("_total_import_count: %s", e, exc_info=True)
        self._total_import_count_cache = (total, dll_names)
        return self._total_import_count_cache

    # ---------------- anti-debug ----------------
    def detect_antidebug(self):
        if self._antidebug_cache is not None:
            return self._antidebug_cache
        antidebug_apis = set(self.api_rules.get('antidebug_apis', []))
        detected = []
        try:
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    api_name = imp.name.decode('utf-8', errors='ignore')
                    if api_name in antidebug_apis:
                        detected.append(api_name)
        except PARSE_EXCEPTIONS as e:
            logger.debug("detect_antidebug: %s", e, exc_info=True)
        result = (len(detected) > 0, detected)
        self._antidebug_cache = result
        return result

    # ---------------- crypto ----------------
    def detect_crypto_apis(self):
        if self._crypto_cache is not None:
            return self._crypto_cache
        crypto_apis = self.api_rules.get('crypto_apis', {})
        indicators = {'windows_crypto': False, 'cng_bcrypt': False, 'openssl': False, 'detected_apis': []}
        try:
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    api_name = imp.name.decode('utf-8', errors='ignore')
                    for family, names in crypto_apis.items():
                        if api_name in names:
                            indicators[family] = True
                            indicators['detected_apis'].append(api_name)
        except PARSE_EXCEPTIONS as e:
            logger.debug("detect_crypto_apis: %s", e, exc_info=True)
        self._crypto_cache = indicators
        return indicators

    # ---------------- TLS callbacks ----------------
    def detect_tls_callbacks(self):
        if self._tls_cache is not None:
            return self._tls_cache
        callbacks = []
        try:
            tls_dir = getattr(self.pe, 'DIRECTORY_ENTRY_TLS', None)
            if tls_dir is not None:
                addr = tls_dir.struct.AddressOfCallBacks
                if addr:
                    is_64 = self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
                    ptr_size = 8 if is_64 else 4
                    image_base = self.pe.OPTIONAL_HEADER.ImageBase
                    rva = addr - image_base
                    for i in range(64):  #capped: guarding against a corrupt/hostile TLS directory i guess
                        try:
                            raw = self.pe.get_data(rva + i * ptr_size, ptr_size)
                        except PARSE_EXCEPTIONS:
                            break
                        ptr = int.from_bytes(raw, 'little')
                        if ptr == 0:
                            break
                        callbacks.append(ptr)
        except PARSE_EXCEPTIONS as e:
            logger.debug("detect_tls_callbacks: %s", e, exc_info=True)
        result = (len(callbacks) > 0, callbacks)
        self._tls_cache = result
        return result

    # ---------------- overlay + Authenticode ----------------
    def detect_overlay(self):
        if self._overlay_cache is not None:
            return self._overlay_cache
        has_overlay, overlay_size, overlay_entropy, likely_signature = False, 0, 0.0, False
        try:
            file_size = len(self.pe.__data__)
            last_end = max(
                (s.PointerToRawData + s.SizeOfRawData for s in self.pe.sections),
                default=file_size
            )
            if file_size > last_end:
                overlay_size = file_size - last_end
                has_overlay = True
                sample = self.pe.__data__[last_end:last_end + min(overlay_size, 4 * 1024 * 1024)]
                overlay_entropy = self.calculate_entropy(sample)

                cert_offset, cert_size = 0, 0
                try:
                    idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_SECURITY')
                    dd = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                    cert_offset, cert_size = dd.VirtualAddress, dd.Size
                except PARSE_EXCEPTIONS:
                    for dd in getattr(self.pe.OPTIONAL_HEADER, 'DATA_DIRECTORY', []):
                        if getattr(dd, 'name', '') == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                            cert_offset, cert_size = dd.VirtualAddress, dd.Size
                            break
                if cert_size > 0 and abs(cert_offset - last_end) <= 16 and cert_size >= overlay_size * 0.9:
                    likely_signature = True
        except PARSE_EXCEPTIONS as e:
            logger.debug("detect_overlay: %s", e, exc_info=True)
        result = (has_overlay, overlay_size, overlay_entropy, likely_signature)
        self._overlay_cache = result
        return result

    # ---------------- .NET detection + import evasion ----------------
    def is_dotnet_assembly(self):
        try:
            for dd in getattr(self.pe.OPTIONAL_HEADER, 'DATA_DIRECTORY', []):
                if getattr(dd, 'name', '') == 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR' and dd.Size > 0:
                    return True
        except PARSE_EXCEPTIONS:
            pass
        return False

    def detect_import_evasion(self):
        if self._import_evasion_cache is not None:
            return self._import_evasion_cache
        total_imports, dll_names = self._total_import_count()
        code_size = 0
        try:
            for section in self.pe.sections:
                if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                    code_size += section.SizeOfRawData
        except PARSE_EXCEPTIONS as e:
            logger.debug("detect_import_evasion (code_size): %s", e, exc_info=True)

        dynamic_resolvers_present = False
        try:
            for entry in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', errors='ignore') in (
                        'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'GetProcAddress',
                    ):
                        dynamic_resolvers_present = True
        except PARSE_EXCEPTIONS:
            pass

        is_dotnet = self.is_dotnet_assembly()
        suspicious = (
            not is_dotnet
            and code_size > 64 * 1024
            and ((0 < total_imports < 15 and dynamic_resolvers_present) or total_imports == 0)
        )
        result = {
            'suspicious': suspicious, 'total_imports': total_imports,
            'code_size': code_size, 'dynamic_resolvers_present': dynamic_resolvers_present,
            'is_dotnet': is_dotnet,
        }
        self._import_evasion_cache = result
        return result

    # ---------------- section anomalies ----------------
    def analyze_section_anatomy(self):
        anomalies = []
        try:
            prev_va_end = None
            section_names_seen = []
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_names_seen.append(name)
                flags = section.Characteristics
                writable = bool(flags & IMAGE_SCN_MEM_WRITE)
                executable = bool(flags & IMAGE_SCN_MEM_EXECUTE)

                if writable and executable:
                    anomalies.append({'section': name, 'severity': 'critical',
                                       'issue': 'Writable AND executable (RWX) -- classic self-modifying-code / injection marker'})
                if name and name not in STANDARD_SECTION_NAMES:
                    anomalies.append({'section': name, 'severity': 'info',
                                       'issue': f'Non-standard section name "{name}"'})

                raw, virt = section.SizeOfRawData, section.Misc_VirtualSize
                if raw > 0 and virt > 0 and (virt / raw) > 10:
                    anomalies.append({'section': name, 'severity': 'warning',
                                       'issue': f'Virtual size is {virt/raw:.1f}x its raw size -- likely inflates/unpacks at runtime'})

                va_start = section.VirtualAddress
                va_end = va_start + max(virt, raw)
                if prev_va_end is not None and va_start < prev_va_end:
                    anomalies.append({'section': name, 'severity': 'warning',
                                       'issue': 'Overlaps the previous section in virtual address space'})
                prev_va_end = va_end

            n = len(self.pe.sections)
            if n <= 2:
                anomalies.append({'section': '(section table)', 'severity': 'warning',
                                   'issue': f'Only {n} section(s) total -- unusually few for a normal compiled binary, consistent with a packer stub'})
            elif n >= 12:
                anomalies.append({'section': '(section table)', 'severity': 'info',
                                   'issue': f'{n} sections total -- unusually many, worth checking whether they map to real compiler output'})

            non_standard = sum(1 for nm in section_names_seen if nm not in STANDARD_SECTION_NAMES)
            if section_names_seen and non_standard == len(section_names_seen):
                anomalies.append({'section': '(section table)', 'severity': 'critical',
                                   'issue': 'Every section has a non-standard name -- the whole section table was likely rewritten by a packer/protector'})
        except PARSE_EXCEPTIONS as e:
            logger.debug("analyze_section_anatomy: %s", e, exc_info=True)
        return anomalies

    # ---------------- embedded binaries ----------------
    def scan_embedded_binaries(self, max_hits_per_section=5):
        found = []
        try:
            first_section = self.pe.sections[0] if self.pe.sections else None
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                data = section.get_data()
                offset, hits = 0, 0
                while hits < max_hits_per_section:
                    idx = data.find(b'MZ', offset)
                    if idx == -1:
                        break
                    is_self = (section is first_section and idx == 0)
                    if not is_self and idx + 0x40 <= len(data):
                        try:
                            e_lfanew = int.from_bytes(data[idx + 0x3C:idx + 0x40], 'little')
                            pe_off = idx + e_lfanew
                            if 0 < e_lfanew < len(data) and pe_off + 4 <= len(data) and data[pe_off:pe_off + 2] == b'PE':
                                found.append({'section': name, 'offset': idx, 'size_hint': len(data) - idx})
                                hits += 1
                        except PARSE_EXCEPTIONS:
                            pass
                    offset = idx + 2
        except PARSE_EXCEPTIONS as e:
            logger.debug("scan_embedded_binaries: %s", e, exc_info=True)
        return found

    def get_embedded_binary_bytes(self, section_name, offset, max_size=5 * 1024 * 1024):
        try:
            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if name == section_name:
                    return section.get_data()[offset:offset + max_size]
        except PARSE_EXCEPTIONS as e:
            logger.debug("get_embedded_binary_bytes: %s", e, exc_info=True)
        return b''

    # ---------------- hashes: file hash / imphash / rich header ----------------
    def compute_hashes(self):
        """
        File hash triad + imphash + a best-effort Rich Header hash.

        Imphash uses pefile's own get_imphash() (requires the `pefile`
        package to be built with the imphash extra -- if unavailable,
        reported as None rather than raising).

        Rich Header hashing has no single official standard; this
        implements the widely-used approach (XOR-decode the @comp.id
        array with the header's own checksum key, hash the decoded
        dword sequence) so results are internally consistent and
        comparable across runs of this tool, but may not byte-for-byte
        match every other tool's "rich hash" if their exact packing of
        the dwords differs.
        """
        if self._hashes_cache is not None:
            return self._hashes_cache

        data = self.pe.__data__
        hashes = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'imphash': None,
            'rich_hash': None,
        }

        try:
            hashes['imphash'] = self.pe.get_imphash()
        except PARSE_EXCEPTIONS as e:
            logger.debug("get_imphash failed: %s", e, exc_info=True)
        except AttributeError:
            logger.debug("pefile build has no get_imphash() -- skipping imphash")

        try:
            rich = getattr(self.pe, 'RICH_HEADER', None)
            if rich is not None and getattr(rich, 'values', None):
                dword_bytes = b''.join((v & 0xFFFFFFFF).to_bytes(4, 'little') for v in rich.values)
                hashes['rich_hash'] = hashlib.md5(dword_bytes).hexdigest()
        except PARSE_EXCEPTIONS as e:
            logger.debug("rich header hash failed: %s", e, exc_info=True)

        self._hashes_cache = hashes
        return hashes
