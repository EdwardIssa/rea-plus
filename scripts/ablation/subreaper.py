#!/usr/bin/env python3
"""Subreaper shim for the ablation harness namespace chain.

Sets PR_SET_CHILD_SUBREAPER on itself, then execs the dynamic worker, so
orphaned descendants of an escaping fixture (double-fork, setsid) reparent
to the worker and stay inside the supervisor's /proc parentage accounting
instead of escaping to the host init. Usage: subreaper.py <worker> <job>
"""
import ctypes
import os
import sys

PR_SET_CHILD_SUBREAPER = 36
ctypes.CDLL(None).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
os.execvp("node", ["node", sys.argv[1], sys.argv[2]])
