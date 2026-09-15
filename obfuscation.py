
import base64
import re
from collections import Counter

from .logutil import logger, PARSE_EXCEPTIONS

_B64_RE = re.compile(rb'^[A-Za-z0-9+/]+={0,2}$')
_PRINTABLE_RE = re.compile(rb'[ -~]{4,}')
_NON_PRINTABLE_BYTES = bytes(b for b in range(256) if not (32 <= b <= 126))
_NON_ALNUM_SPACE_BYTES = bytes(b for b in range(256)
                                if not ((65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b == 32))


def _count_printable(data):
    return len(data.translate(None, delete=_NON_PRINTABLE_BYTES))


def _count_alnum_space(data):
    return len(data.translate(None, delete=_NON_ALNUM_SPACE_BYTES))


def _make_translate_table(op, key=0):
    if op == 'xor':
        return bytes(b ^ key for b in range(256))
    if op == 'add':
        return bytes((b + key) & 0xFF for b in range(256))
    if op == 'sub':
        return bytes((b - key) & 0xFF for b in range(256))
    if op == 'rol':
        return bytes(((b << key) | (b >> (8 - key))) & 0xFF for b in range(256))
    if op == 'ror':
        return bytes(((b >> key) | (b << (8 - key))) & 0xFF for b in range(256))
    if op == 'not':
        return bytes((~b) & 0xFF for b in range(256))
    raise ValueError(f"unknown op {op!r}")


class ObfuscationAnalyzer:
    def __init__(self, pe):
        self.pe = pe
        self._cipher_cache = None
        self._base64_cache = None
        self._all_strings_cache = None

    # ---------------- string extraction ----------------
    def extract_printable_strings(self, min_length=4):
        """
        Fast plain-ASCII string listing via a single compiled regex pass
        per section (`re.finditer`, C-level under the hood) -- this is
        the "strings(1)"-equivalent view for strings that are ALREADY
        readable, used for the plaintext fallback and general listing.
        Deliberately separate from `_all_strings`, which needs to also
        capture non-printable runs that might decode into something once
        a cipher key is applied -- a pure printable-ASCII regex would
        exclude exactly the data that check needs to see.
        """
        results = []
        try:
            for section in self.pe.sections:
                data = section.get_data()
                results.extend(m.group() for m in _PRINTABLE_RE.finditer(data) if len(m.group()) >= min_length)
        except PARSE_EXCEPTIONS as e:
            logger.debug("extract_printable_strings: %s", e, exc_info=True)
        return results

    def _all_strings(self):
        """
        NUL-delimited chunk extraction across all sections -- this is
        `bytes.split(b'\\x00')`, a single C-level call, NOT a Python
        for-byte loop (that was never actually the bottleneck; the
        bottleneck was the per-key decode step below, now fixed via
        translate tables). Chunks include non-printable runs on purpose,
        since those are exactly what a cipher key might turn into text.
        """
        if self._all_strings_cache is not None:
            return self._all_strings_cache
        min_length, max_chunk_len, max_chunks = 4, 256, 4000
        chunks = []
        try:
            for section in self.pe.sections:
                data = section.get_data()
                for raw in data.split(b'\x00'):
                    if len(chunks) >= max_chunks:
                        self._all_strings_cache = chunks
                        return chunks
                    if len(raw) >= min_length:
                        chunks.append(raw[:max_chunk_len])
        except PARSE_EXCEPTIONS as e:
            logger.debug("_all_strings: %s", e, exc_info=True)
        self._all_strings_cache = chunks
        return chunks

    # ---------------- text-quality gates ----------------
    @staticmethod
    def _printable_ratio_ok(data, threshold=0.8):
        if not data:
            return False
        return _count_printable(data) > len(data) * threshold

    @staticmethod
    def _looks_like_real_text(data, min_len=4):
        """
        Stricter than raw printable-ratio: random bytes land in printable
        ASCII about a third of the time by chance, so "80% printable"
        alone passes garbage disturbingly often on short strings. Also
        requires character diversity, a plausible letter/digit/space mix,
        and no absurd single-character runs.
        """
        if not data or len(data) < min_len:
            return False
        n = len(data)
        if _count_printable(data) < n * 0.85:
            return False
        if _count_alnum_space(data) < n * 0.55:
            return False
        if len(set(data)) / n < 0.25:
            return False
        longest_run, run = 1, 1
        for i in range(1, n):
            if data[i] == data[i - 1]:
                run += 1
                longest_run = max(longest_run, run)
            else:
                run = 1
        return longest_run <= max(4, n // 3)

    def _decoded_ok(self, data):
        return self._printable_ratio_ok(data) and self._looks_like_real_text(data)

    def _is_candidate_for_decoding(self, raw_string, plaintext_threshold=0.85):
        """A string is only a decode CANDIDATE if it doesn't already look
        like plaintext -- otherwise "decoding" it just scrambles real text
        (e.g. small XOR keys can incidentally keep ASCII letters printable)."""
        return not self._printable_ratio_ok(raw_string, threshold=plaintext_threshold)

    def detect_cipher_operations(self, show_progress=None):
        """
        show_progress: optional callable(current, total, label) -- kept
        as a callback rather than a hardcoded terminal progress bar so
        this module has zero display-layer dependencies.
        """
        if self._cipher_cache is not None:
            return self._cipher_cache

        strings = self._all_strings()
        results = {}
        if not strings:
            self._cipher_cache = results
            return results

        min_count = max(5, int(0.02 * len(strings)))
        min_fraction = 0.25

        def is_real_hit(count):
            return count >= min_count and (count / len(strings)) >= min_fraction

        candidate_strings = [s for s in strings if self._is_candidate_for_decoding(s)]

        total_steps = 256 * 3 + 7 + 7 + 1 + 3 + 1
        step = [0]

        def tick(label):
            step[0] += 1
            if show_progress:
                show_progress(step[0], total_steps, label)

        for op_name, result_key, key_range in (('xor', 'XOR', range(1, 256)),
                                                 ('add', 'ADD', range(1, 256)),
                                                 ('sub', 'SUB', range(1, 256))):
            hits = {}
            for key in key_range:
                table = _make_translate_table(op_name, key)
                count = sum(1 for s in candidate_strings if self._decoded_ok(s.translate(table)))
                if is_real_hit(count):
                    hits[key] = count
                tick(f"Testing {result_key}")
            if hits:
                results[result_key] = hits

        for op_name, result_key in (('rol', 'ROL (bit-rotate left)'), ('ror', 'ROR (bit-rotate right)')):
            hits = {}
            for shift in range(1, 8):
                table = _make_translate_table(op_name, shift)
                count = sum(1 for s in candidate_strings if self._decoded_ok(s.translate(table)))
                if is_real_hit(count):
                    hits[shift] = count
                tick(f"Testing {result_key}")
            if hits:
                results[result_key] = hits

        table = _make_translate_table('not')
        not_count = sum(1 for s in candidate_strings if self._decoded_ok(s.translate(table)))
        tick("Testing NOT")
        if is_real_hit(not_count):
            results['NOT (bitwise complement)'] = {0: not_count}

        for keylen in (2, 3, 4):
            total_len = sum(len(s) for s in candidate_strings)
            if total_len < keylen * 40:
                tick(f"Testing multi-byte XOR ({keylen})")
                continue
            columns = [Counter() for _ in range(keylen)]
            for s in candidate_strings:
                for i, b in enumerate(s):
                    columns[i % keylen][b] += 1
            key = bytearray(keylen)
            for pos in range(keylen):
                if columns[pos]:
                    key[pos] = columns[pos].most_common(1)[0][0] ^ 0x20  # assume ' '
            key = bytes(key)
            if key != b'\x00' * keylen:
                count = sum(1 for s in candidate_strings
                            if self._decoded_ok(bytes(b ^ key[i % keylen] for i, b in enumerate(s))))
                if is_real_hit(count):
                    results.setdefault('XOR (multi-byte)', {})[key] = count
            tick(f"Testing multi-byte XOR ({keylen})")

        base64_hits = self._detect_base64_strings(strings)
        tick("Testing Base64")
        if base64_hits:
            results['BASE64'] = {0: len(base64_hits)}
            self._base64_cache = base64_hits

        self._cipher_cache = results
        return results

    @staticmethod
    def _detect_base64_strings(strings, min_len=12):
        hits = []
        for s in strings:
            if len(s) < min_len or not _B64_RE.match(s):
                continue
            padded = s + b'=' * (-len(s) % 4)
            try:
                decoded = base64.b64decode(padded, validate=True)
            except (ValueError, base64.binascii.Error):
                continue
            if not decoded:
                continue
            printable = _count_printable(decoded)
            looks_textual = printable > len(decoded) * 0.85 and len(set(decoded)) / len(decoded) > 0.2
            looks_binary_magic = decoded[:2] in (b'MZ', b'PK') or decoded[:4] == b'\x7fELF'
            if looks_textual or looks_binary_magic:
                hits.append((s, decoded))
        return hits

    def decode_strings_preview(self, max_items=15):
        cipher = self.detect_cipher_operations()
        strings = self._all_strings()
        if not strings:
            return {'op': None, 'key': None, 'strings': []}

        if not cipher:
            keywords = [b'http', b'.dll', b'.exe', b'\\', b'cmd', b'password',
                        b'admin', b'C:\\', b'.php', b'.onion']
            picks = [s for s in strings if any(k in s for k in keywords) and self._looks_like_real_text(s)]
            picks = sorted(set(picks), key=len, reverse=True)[:max_items]
            return {'op': None, 'key': None, 'strings': [p.decode('utf-8', errors='ignore') for p in picks]}

        non_base64 = {k: v for k, v in cipher.items() if k != 'BASE64'}
        if not non_base64 and 'BASE64' in cipher:
            decoded_pairs = self._base64_cache or []
            picks = sorted(set(d.decode('utf-8', errors='ignore') for _, d in decoded_pairs
                                if all(32 <= b <= 126 for b in d)), key=len, reverse=True)[:max_items]
            return {'op': 'BASE64', 'key': None, 'strings': picks}

        best_op, best_candidates = max(non_base64.items(), key=lambda kv: max(kv[1].values()))
        best_key = max(best_candidates.items(), key=lambda kv: kv[1])[0]

        def apply_op(data):
            if best_op == 'XOR':
                return data.translate(_make_translate_table('xor', best_key))
            if best_op == 'XOR (multi-byte)':
                return bytes(b ^ best_key[i % len(best_key)] for i, b in enumerate(data))
            if best_op == 'ADD':
                return data.translate(_make_translate_table('add', best_key))
            if best_op == 'SUB':
                return data.translate(_make_translate_table('sub', best_key))
            if best_op.startswith('ROL'):
                return data.translate(_make_translate_table('rol', best_key))
            if best_op.startswith('ROR'):
                return data.translate(_make_translate_table('ror', best_key))
            if best_op.startswith('NOT'):
                return data.translate(_make_translate_table('not'))
            return data

        decoded = []
        for s in strings:
            if self._is_candidate_for_decoding(s):
                dec = apply_op(s)
                if self._decoded_ok(dec):
                    decoded.append(dec.decode('utf-8', errors='ignore'))
            elif self._printable_ratio_ok(s):
                decoded.append(s.decode('utf-8', errors='ignore'))
        decoded = sorted(set(decoded), key=len, reverse=True)[:max_items]
        return {'op': best_op, 'key': best_key, 'strings': decoded}
