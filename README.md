# SysTorch

Every time I got a new sample I didn't know, I'd do the same five things: check what it imports, check entropy, see if it's packed, see if it's bullshitting me about its import table, then figure out if this is a 10-minute thing or I might need to quit reverse engineering thing.
Kinda got tired of doing that by hand.

SysTorch is a PE triage tool. You throw a binary at it, it tells you what you're actually looking at: imports, entropy, TLS callbacks, overlay data, packed or not, if it's hiding its API calls on purpose, and spits out a difficulty score so you know whether to fire up Ghidra or just act like you never saw this exe.

It's not a disassembler. It's not gonna solve your crackme for you. Just tells you how much this is gonna suck before you solve it.

---

## Running It

Two ways to use it, depending on what you want.

**Just drag a file onto it, or use a path:**

```
systorch.exe sample.exe
```

No menus, reads the file, shows you the dashboard, drops you into a shell already pointed at the binary. This is the joe biden way.

**Or run it with nothing:**

```
systorch.exe
```

Asks for a file, same shell after. For when you got time to waste.

**Got 50 samples and don't wanna sit there watching it? Use flags:**

```
systorch.exe samples\*.exe --fast --quiet --html report.html
```

| Flag | Does |
|---|---|
| `--fast` | Cuts every artificial delay. No typewriter effect, no loading bars. |
| `--quiet` | Also kills the boot sequence and ASCII art. Script-friendly. |
| `--debug` | Full tracebacks instead of quietly skipping malformed sections. |
| `--html PATH` | Dumps a self-contained HTML report. |
| `--yara-rules DIR` | Point it at your own `.yar` files if you have `yara-python` installed. |

Heads up: double-clicking doesn't pass arguments on Windows. If you want `--fast` you gotta use a terminal.

---

## Once You're In The Shell

```
systorch(sample.exe)>
```

Type `help` to see the prompts:

| Command | Does |
|---|---|
| `imports` | Shows sketchy API imports, grouped up |
| `entropy` | Entropy per section, colors make packed stuff pop |
| `tls` | TLS callbacks — runs before ur breakpoint even hits |
| `overlay` | Junk at the end past the last section (payload or whatever) |
| `evasion` | Checks if they're hiding their imports on purpose |
| `protectors` | Known packer signatures |
| `behavior` | Takes the raw imports and figures out what they're actually doing, with MITRE tags |
| `score` | The verdict — how hard is this, static analysis vs dynamic stuff, all the clues added up |
| `full` | Runs all of em in order if you want the full story |
| `compare <file>` | Sticks two files' scores side by side |
| `load <file>` | Swaps to a different file without restarting |

`score` is what matters. Everything else is just evidence; `score` is the answer.

---

## Reading The Output

Four colors, four things they mean:

- **[CRITICAL] (red)** — Pay attention to this. RWX sections, confirmed packers, process injection shit.
- **[WARNING] (amber)** — Sus but not proof. Crypto APIs, anti-debug, medium-confidence packer hits.
- **[NOTICE] (blue)** — Just facts. Section counts, structural stuff.
- **[CLEAR] (green)** — Checked it, nothing there.

If something's red everywhere, that's not a bug. That's the tool working right. And you might start reconsidering your life decisions.
Os_Ring0 ;)
