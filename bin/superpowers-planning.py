#!/usr/bin/env python3
"""Compatibility entry point for the original Claude/Superpowers planning CLI."""

from planning import *  # noqa: F403
from planning import main


if __name__ == "__main__":
    raise SystemExit(main(legacy=True))
