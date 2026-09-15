"""
Shared logging configuration.

Previously every analyzer method did `except Exception as e: print(...)`,
which swallows real bugs (TypeError, IndexError from our own code) right
alongside expected parsing failures on malformed/untrusted PE files --
indistinguishable from each other, and invisible unless you were staring
at stdout at the right moment.

The fix used throughout this package: catch a SPECIFIC, deliberately
chosen tuple of exceptions at each call site (the ones that genuinely can
happen when parsing arbitrary/malformed PE data), log them at DEBUG level
with a full traceback, and let anything outside that tuple propagate --
because if it's not in the tuple, it's probably our bug, not the file's.

Run with --debug to see every logged parsing hiccup and its stack trace;
without it, this stays quiet the way most CLI tools default to.
"""

import logging
import struct

logger = logging.getLogger("systorch")

# Exceptions that are expected, recoverable failure modes when parsing
# arbitrary/malformed/hostile PE files -- NOT a signal of a code bug here.
# Any exception outside this tuple is deliberately left to propagate.
PARSE_EXCEPTIONS = (ValueError, IndexError, AttributeError, KeyError, struct.error)


def configure_logging(debug=False):
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def log_parse_issue(context, exc):
    logger.debug("%s: %s: %s", context, type(exc).__name__, exc, exc_info=True)
