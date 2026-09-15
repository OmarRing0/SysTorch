
class BehaviorAnalyzer:
    def __init__(self, pe_structure, mitre_mapping):
        self.pe_structure = pe_structure
        self.mitre_mapping = mitre_mapping or {}

    def _attck(self, name):
        return self.mitre_mapping.get(name)

    def detect_patterns(self):
        imports = self.pe_structure.analyze_imports()
        crypto = self.pe_structure.detect_crypto_apis()
        patterns = {}

        def add(name, description, evidence):
            evidence = sorted(set(evidence))
            if evidence:
                patterns[name] = {
                    'description': description,
                    'evidence': evidence,
                    'attck': self._attck(name),
                }

        encryption_evidence = list(imports.get('Encryption', []))
        encryption_evidence += [a for a in crypto['detected_apis'] if a not in encryption_evidence]
        file_ops = imports.get('File System Operations', [])
        has_delete = any(a.startswith('DeleteFile') for a in file_ops)
        if encryption_evidence and file_ops and has_delete:
            add('Ransomware-style file encryption',
                'Encrypts data and deletes the originals -- the core behavior of ransomware',
                encryption_evidence + [a for a in file_ops if a.startswith(('DeleteFile', 'WriteFile', 'CreateFile'))])

        injection_evidence = list(imports.get('Process Injection & Code Execution', []))
        injection_evidence += list(imports.get('Stealth & Code Injection', []))
        if injection_evidence:
            add('Process injection / remote code execution',
                'Allocates memory and executes code inside another process -- a classic injection chain',
                injection_evidence)

        net = imports.get('Networking', [])
        persist = imports.get('Persistence', [])
        dynload = imports.get('Dynamic Loading', [])
        if net and (persist or dynload):
            add('Network command-and-control pattern',
                'Talks to the network and persists or dynamically loads code -- matches a C2/botnet client',
                list(net) + list(persist))

        hook = imports.get('Hooking & Keylogging', [])
        if any(a in ('GetAsyncKeyState', 'GetKeyState') for a in hook) or \
           ('SetWindowsHookExA' in hook or 'SetWindowsHookExW' in hook):
            add('Keylogging / input capture',
                'Hooks or polls keyboard state -- matches keylogger/spyware behavior',
                hook)

        anti = imports.get('Anti-Analysis/VM Detection', [])
        mem = imports.get('Memory Inspection & Evasion', [])
        if anti and mem:
            add('Analysis evasion',
                'Checks for debuggers/VMs and inspects its own process memory -- built to resist analysis',
                anti + mem)

        priv = imports.get('Privilege Escalation', [])
        if priv:
            add('Privilege escalation attempt',
                'Adjusts security tokens or impersonates users to gain higher privileges',
                priv)

        svc_or_run_key = [a for a in persist if 'Service' in a or 'Reg' in a]
        if svc_or_run_key:
            add('Persistence mechanism',
                'Installs itself to survive reboot via services or registry run keys',
                svc_or_run_key)

        return patterns
