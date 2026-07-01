#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentScan Evaluation Kit — standalone benchmark runner.

This is a thin wrapper around `agentscan benchmark` (the same logic now
ships as a first-class CLI command). Kept here so the evaluation kit is
self-documenting and runnable even by someone who hasn't read the CLI
docs — `python run_benchmark.py` is the obvious thing to try in this
directory.

For the canonical, maintained scenario list see agentscan/benchmark.py
in the main package — this script does not duplicate it.

Usage:
    python run_benchmark.py
"""
import sys
from agentscan.benchmark import run_benchmark

if __name__ == "__main__":
    sys.exit(run_benchmark())
