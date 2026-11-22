/**
 * The PR_SET_CHILD_SUBREAPER shim as an embedded text asset (the
 * GhidraBridgeSources pattern): the application writes this source to the
 * run's temp dir at launch and the namespace chain execs it before the
 * dynamic worker, so orphaned descendants of an escaping target
 * (double-fork, setsid) reparent to the worker and stay inside the
 * supervisor's /proc parentage accounting instead of escaping to the host
 * init. Usage: subreaper.py <worker> <job>
 *
 * Before the exec, the shim writes a marker beside the job naming its own
 * pid. The exec preserves the pid, so the worker can prove from the
 * marker that it holds the subreaper role and that its descendant
 * accounting is authoritative. Without the marker (the shim dropped from
 * the chain), the worker reports its accounting as unarmed and the
 * application refuses to claim a containment verdict for the run.
 */
export const SUBREAPER_SHIM_SOURCE = `#!/usr/bin/env python3
import ctypes
import json
import os
import sys

PR_SET_CHILD_SUBREAPER = 36
ctypes.CDLL(None).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
marker_path = os.path.join(
    os.path.dirname(os.path.abspath(sys.argv[2])), "subreaper.json"
)
with open(marker_path, "w") as marker:
    json.dump({"pid": os.getpid(), "subreaper": True}, marker)
os.execvp("node", ["node", sys.argv[1], sys.argv[2]])
`;

/** The marker file name the shim writes beside the run's job file. */
export const SUBREAPER_MARKER_FILE = "subreaper.json";
