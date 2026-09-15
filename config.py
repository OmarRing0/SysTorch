"""
Loads the externalized rule files (rules/apis.json, rules/mitre_mapping.json,
rules/protector_signatures.json) so analysts can add a new ransomware API
or protector signature by editing JSON, not Python source.

Every loader accepts an optional explicit path (so a user can point at
their own rules file entirely) and otherwise falls back to the bundled
defaults shipped in rules/.
"""

import json
import os

from .logutil import logger

_RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')


def _load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_api_rules(path=None):
    path = path or os.path.join(_RULES_DIR, 'apis.json')
    try:
        return _load_json(path)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not load API rules from %s (%s) -- suspicious-API "
                        "categorization will be empty until this is fixed.", path, e)
        return {"categories": {}, "antidebug_apis": [], "crypto_apis": {}}


def load_mitre_mapping(path=None):
    path = path or os.path.join(_RULES_DIR, 'mitre_mapping.json')
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not load MITRE mapping from %s (%s) -- ATT&CK "
                        "annotations will be omitted.", path, e)
        return {}
    return {k: v for k, v in data.items() if not k.startswith('_')}


def load_protector_signatures(path=None):
    path = path or os.path.join(_RULES_DIR, 'protector_signatures.json')
    try:
        return _load_json(path)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not load protector signatures from %s (%s) -- "
                        "known-packer scanning will find nothing.", path, e)
        return {"section_names": {}, "import_dlls": {}, "string_markers": {}, "entry_point_signatures": []}


def default_yara_rules_dir():
    d = os.path.join(_RULES_DIR, 'yara')
    return d if os.path.isdir(d) else None
