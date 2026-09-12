"""
Terminal display layer: colors, boot sequence, section chrome, and the
--fast/--quiet timing controls. Kept separate from the analysis logic so
the analyzer classes never need to know or care how (or whether) their
results get animated onto a screen -- they just return data.
"""

import os
import re
import sys
import time
import random

from . import art

# ============================================================
#  THEME
# ============================================================
# Structural/chrome colors (headers, borders, dividers) stay green --
# that's just the terminal's visual identity, not a severity signal.
GREEN = '\033[32m'
BRIGHT_GREEN = '\033[92m'
BOLD_GREEN = '\033[1;92m'
DIM_GREEN = '\033[2;32m'
RESET = '\033[0m'
BOLD = '\033[1m'
BRIGHT_WHITE = '\033[1;97m'

# Muted label color for the key/value hierarchy -- labels get dimmed so
# the actual forensic values (the part someone is scanning for) are what
# jumps out, instead of every line being the same flat brightness.
DIM_LABEL = '\033[90m'

# Hex addresses / byte sequences get a distinct accent so they read as
# "data", not just more text -- muted magenta.
HEX_COLOR = '\033[35m'

# --- Traffic-light severity colors: this IS the signal. ---
CRITICAL = '\033[1;91m'   # bold red (also used for the CRITICAL badge text)
WARNING = '\033[1;33m'    # amber   (also used for the WARNING badge text)
INFO = '\033[38;5;39m'    # electric blue (NOTICE)
SAFE = '\033[38;5;48m'    # mint green (CLEAR)

# Solid "pill" backgrounds for the two severities that need to physically
# jump out of a scrolling wall of text -- CRITICAL and WARNING render as
# filled badges, not just colored text.
_CRITICAL_PILL_BG = '\033[41;1;97m'   # solid red bg, bold white text
_WARNING_PILL_BG = '\033[43;1;30m'    # solid yellow bg, black text

_SEVERITY_COLORS = {'critical': CRITICAL, 'warning': WARNING, 'info': INFO, 'safe': SAFE}

_BADGES = {
    'critical': (_CRITICAL_PILL_BG, ' \u2716 CRITICAL '),   # ✖  (12 chars, pill bg)
    'warning': (_WARNING_PILL_BG, ' \u25b2 WARNING  '),      # ▲  (12 chars, pill bg)
    'info': (INFO, ' \u25c6 NOTICE   '),                     # ◆  (12 chars, plain text)
    'safe': (SAFE, ' \u2714 CLEAR    '),                     # ✔  (12 chars, plain text)
}

_HEX_RE = re.compile(r'\b0x[0-9a-fA-F]+\b')


def severity_color(sev):
    return _SEVERITY_COLORS.get(sev, INFO)


def sev_badge(sev):
    """The colored badge text alone, e.g. ' ✖ CRITICAL ' with its pill
    background -- for embedding inline rather than starting a whole line."""
    color, text = _BADGES.get(sev, _BADGES['info'])
    return f"{color}{text}{RESET}"


def hexify(text):
    """Wraps every 0x... hex literal in a string with the accent color --
    used for addresses, offsets, and byte sequences printed inline."""
    return _HEX_RE.sub(lambda m: f"{HEX_COLOR}{m.group()}{RESET}", text)


def sev_line(sev, text, indent='  '):
    """One line of findings output: badge + text. This is the
    traffic-light system in practice -- badges survive being read by
    someone colorblind (icon + word), unlike color alone."""
    print(f"{indent}{sev_badge(sev)} {hexify(text)}")


def kv(label, value, indent='  ', value_color=BRIGHT_WHITE):
    """Dimmed label, muted arrow, bright value -- the high-contrast
    key/value hierarchy. Use for hashes, addresses, counts: anything
    where the label is just orientation and the value is the payload."""
    print(f"{indent}{DIM_LABEL}{label} \u203a{RESET} {value_color}{hexify(str(value))}{RESET}")


def tree(items, indent='  '):
    """Renders a flat list as tree branches (├──/└──) instead of a plain
    indented dump -- used for APIs under an import category, evidence
    under a behavior pattern, etc."""
    for i, item in enumerate(items):
        branch = '\u2514\u2500\u2500' if i == len(items) - 1 else '\u251c\u2500\u2500'
        print(f"{indent}{DIM_LABEL}{branch}{RESET} {hexify(str(item))}")


def gauge_bar(fraction, width=30):
    """A static value gauge (entropy, difficulty score): solid/shaded
    Unicode blocks, colored by how far filled it is -- green under 45%,
    amber under 75%, crimson above. Returns the colored bar string only
    (caller prints the label/percentage around it)."""
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(width * fraction))
    if fraction >= 0.75:
        color = CRITICAL
    elif fraction >= 0.45:
        color = WARNING
    else:
        color = SAFE
    bar = '\u2588' * filled + '\u2591' * (width - filled)
    return f"{color}{bar}{RESET}"


# ============================================================
#  TIMING CONTROL (--fast / --quiet)
# ============================================================
class _Timing:
    """Mutable timing state, set once at startup from argparse. A real
    reverse engineer triaging 50 samples should never be stuck waiting on
    typewriter effects -- --fast disables all artificial delay; --quiet
    additionally skips the boot sequence and ASCII art entirely."""
    fast = False
    quiet = False


TIMING = _Timing()


def configure(fast=False, quiet=False):
    TIMING.fast = fast or quiet
    TIMING.quiet = quiet


def _sleep(seconds):
    if TIMING.fast:
        return
    time.sleep(seconds)


def clear_screen():
    if TIMING.quiet:
        return
    os.system('cls' if os.name == 'nt' else 'clear')


def typewriter(text, delay=0.015, color=BRIGHT_GREEN, end='\n'):
    if TIMING.fast:
        print(f"{color}{text}{RESET}", end=end)
        return
    for ch in text:
        sys.stdout.write(f"{color}{ch}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)
    sys.stdout.flush()


def fade_in_art(art_text, frames=3, frame_delay=0.11, colors=(DIM_GREEN, GREEN, BRIGHT_GREEN)):
    if TIMING.quiet:
        return
    lines = art_text.strip('\n').split('\n')
    if TIMING.fast:
        for line in lines:
            print(f"{colors[-1]}{line}{RESET}")
        return
    height = len(lines)
    frames = min(frames, len(colors))
    for i in range(frames):
        color = colors[i]
        if i > 0:
            sys.stdout.write(f"\033[{height}A")
        for line in lines:
            sys.stdout.write(f"\033[2K{color}{line}{RESET}\n")
        sys.stdout.flush()
        if i < frames - 1:
            time.sleep(frame_delay)


def show_progress_bar(current, total, label="Working", width=24):
    """Calibrated tracking-bar style loading indicator: ╢████░░░░░╟ 45.0%"""
    if TIMING.quiet:
        return
    frac = current / total if total else 1
    filled = int(width * frac)
    bar = '\u2588' * filled + '\u2591' * (width - filled)
    sys.stdout.write(f"\r{DIM_LABEL}{label}{RESET} {BRIGHT_GREEN}\u2562{bar}\u255f{RESET} "
                      f"{BRIGHT_WHITE}{frac*100:5.1f}%{RESET}")
    sys.stdout.flush()
    if current >= total:
        print()


def fake_loading(label, duration=0.5, steps=20):
    if TIMING.fast:
        return
    for i in range(steps + 1):
        show_progress_bar(i, steps, label)
        time.sleep(duration / steps)


def section_divider(pause=0.0):
    if TIMING.quiet:
        print()
        return
    print(f"\n{DIM_GREEN}{'\u2500' * 60}{RESET}\n")
    if pause:
        _sleep(pause)


def print_header(title):
    """Tactical pill-style box chrome: ┌──[ TITLE ]──────────────┐"""
    if TIMING.quiet:
        print(f"\n== {title} ==")
        return
    width = 60
    inner = f" {title} "
    left = "\u250c\u2500\u2500["
    tail_len = max(0, width - len(left) - len(inner) - 1)
    right = "]" + "\u2500" * tail_len + "\u2510"
    print(f"\n{BOLD_GREEN}{left}{RESET}{BOLD}{BRIGHT_WHITE}{inner}{RESET}{BOLD_GREEN}{right}{RESET}")
    print(f"{BOLD_GREEN}\u2514{'\u2500' * (width - 2)}\u2518{RESET}\n")


def print_batch_banner(index, total, path):
    """Framed header badge separating files in a bulk-triage run --
    distinct (double-line box) from the single-line section headers so
    it reads as a clear boundary between files at a glance."""
    width = 60
    label = f"FILE {index}/{total} :: {os.path.basename(path)}"
    if len(label) > width - 4:
        label = label[:width - 7] + "..."
    pad = width - 4 - len(label)
    print(f"\n{BOLD_GREEN}\u2554{'\u2550' * (width - 2)}\u2557{RESET}")
    print(f"{BOLD_GREEN}\u2551{RESET} {BRIGHT_WHITE}{label}{RESET}{' ' * pad} {BOLD_GREEN}\u2551{RESET}")
    print(f"{BOLD_GREEN}\u255a{'\u2550' * (width - 2)}\u255d{RESET}")


def print_note(text):
    if TIMING.quiet:
        return
    import textwrap
    wrapped = textwrap.wrap(text, width=68)
    for line in wrapped:
        print(f"  {DIM_GREEN}i {line}{RESET}")
    print()


SECTION_PAUSE = 1.6

BOOT_CHECKLIST = [
    "Mounting /dev/curiosity",
    "Spawning ghost threads",
    "Calibrating skull-o-meter",
    "Bribing the entropy gods",
    "Sharpening the jaw hinge",
    "Warming up the brute-forcer",
]

BOOT_QUOTES = [
    "Every binary tells a story. Some just whisper it in XOR.",
    "Entropy doesn't lie. Difficulty scores sometimes do -- we're fixing that.",
    "Static first. Dynamic when static stops talking.",
]


def boot_checklist():
    if TIMING.quiet:
        return
    for item in BOOT_CHECKLIST:
        sys.stdout.write(f"  {DIM_GREEN}[    ] {item}...{RESET}")
        sys.stdout.flush()
        _sleep(0.09)
        sys.stdout.write(f"\r  {BRIGHT_GREEN}[ {BOLD_GREEN}OK{BRIGHT_GREEN} ] {item}{' ' * 12}{RESET}\n")
        sys.stdout.flush()
    _sleep(0.15)


def welcome_screen():
    clear_screen()
    if TIMING.quiet:
        print("SysTorch -- Static Analysis & RE Difficulty Estimator (quiet mode)")
        return
    boot_checklist()
    print()
    _sleep(0.2)
    fade_in_art(art.BIG_SKULL, frames=3, frame_delay=0.11)
    _sleep(0.35)
    print(f"\n{DIM_GREEN}{'.' * 60}{RESET}")
    _sleep(0.45)
    fade_in_art(art.NAME_ART, frames=2, frame_delay=0.1)
    print()
    _sleep(0.3)
    print(f"{BRIGHT_GREEN}Static Analysis & Reverse Engineering Difficulty Estimator{RESET}")
    print(f"{DIM_GREEN}v2.1 -- SysTorch{RESET}")
    print(f"{DIM_GREEN}\"{random.choice(BOOT_QUOTES)}\"{RESET}")
    print()
    _sleep(0.4)
    fade_in_art(art.CREDIT_ART, frames=2, frame_delay=0.1)
    print(f"{DIM_GREEN}( concept, code & chaos ){RESET}\n")
    _sleep(0.4)


def display_laughing_skull_outro():
    """Shown exactly once, on program exit -- not after every analysis."""
    if TIMING.quiet:
        return
    art_text = art.LAUGHING_SKULL.strip('\n')
    lines = art_text.split('\n')
    height = len(lines)

    print()
    if TIMING.fast:
        for line in lines:
            print(f"{BRIGHT_GREEN}{line}{RESET}")
    else:
        for i, color in enumerate((DIM_GREEN, GREEN, BRIGHT_GREEN)):
            if i > 0:
                sys.stdout.write(f"\033[{height}A")
            for line in lines:
                sys.stdout.write(f"\033[2K{color}{line}{RESET}\n")
            sys.stdout.flush()
            time.sleep(0.12)
        for i in range(3):
            color = WARNING if i % 2 == 0 else BOLD_GREEN
            sys.stdout.write(f"\033[{height}A")
            for line in lines:
                sys.stdout.write(f"\033[2K{color}{line}{RESET}\n")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write(f"\033[{height}A")
        for line in lines:
            sys.stdout.write(f"\033[2K{BRIGHT_GREEN}{line}{RESET}\n")
        sys.stdout.flush()

    print()
    typewriter("  Whatever you found in there, it'll still be there next time.",
               delay=0.006, color=BRIGHT_GREEN)
    print(f"  {DIM_GREEN}SysTorch  --  crafted by Os_Ring0{RESET}\n")


def goodbye():
    display_laughing_skull_outro()
    print()
    typewriter("Closing up shop. Stay curious.", delay=0.02, color=BOLD_GREEN)
    print()

