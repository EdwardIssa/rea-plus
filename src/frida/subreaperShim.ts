/**
 * The PR_SET_CHILD_SUBREAPER shim as an embedded text asset (the
 * GhidraBridgeSources pattern): the application writes this source to the
 * run's temp dir at launch and the namespace chain execs it before the
 * dynamic worker, so orphaned descendants of an escaping target
 * (double-fork, setsid) reparent to the worker and stay inside the
 * supervisor's /proc parentage accounting instead of escaping to the host
 * init. Usage: subreaper.py <worker> <job>
 */
export const SUBREAPER_SHIM_SOURCE = `#!/usr/bin/env python3
import ctypes
import os
import sys

PR_SET_CHILD_SUBREAPER = 36
ctypes.CDLL(None).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
os.execvp("node", ["node", sys.argv[1], sys.argv[2]])
`;
