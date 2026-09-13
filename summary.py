"""
the dashboard I guess
"""

_RANK = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}


class ExecutiveSummary:
    def __init__(self, pe_structure, protectors, behavior, difficulty_result):
        self.pe = pe_structure
        self.prot = protectors
        self.beh = behavior
        self.difficulty = difficulty_result

    def build(self):
        hashes = self.pe.compute_hashes()
        sections = self.pe.analyze_sections()
        avg_entropy = (sum(sections.values()) / len(sections)) if sections else 0.0

        threats = []
        for name, info in self.prot.detect().items():
            threats.append((info['confidence'], f"Packer/Protector: {name} ({info['confidence']})"))
        for name, info in self.beh.detect_patterns().items():
            label = f"Behavior: {name}"
            if info.get('attck'):
                label += f" [{info['attck'].split(' - ')[0]}]"
            threats.append(('HIGH', label))
        imports = self.pe.analyze_imports()
        for cat, apis in imports.items():
            w = self.pe.category_weight(cat)
            if w >= 1.1:
                threats.append(('HIGH', f"{cat} APIs ({len(apis)})"))
            elif w >= 0.8:
                threats.append(('MEDIUM', f"{cat} APIs ({len(apis)})"))

        threats.sort(key=lambda t: _RANK.get(t[0], 1))
        top_threats = [t[1] for t in threats[:3]]
        if not top_threats:
            top_threats = ["No significant threat categories identified"]

        return {
            'md5': hashes['md5'],
            'sha1': hashes['sha1'],
            'sha256': hashes['sha256'],
            'imphash': hashes['imphash'],
            'rich_hash': hashes['rich_hash'],
            'avg_entropy': avg_entropy,
            'top_threats': top_threats,
            'difficulty_label': self.difficulty['label'],
            'difficulty_score': self.difficulty['score'],
        }
