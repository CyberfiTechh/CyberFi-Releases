import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";
import { createHash } from "node:crypto";

const root = resolve(process.argv[2]);
assert(root.startsWith(await realpath(homedir()) + sep) && await realpath(root) === root);
const output = { purpose: "Failure-only fixed-fixture diagnostics; worker limits remain enabled", probes: [] };
try {
    const runtime = join(root, "home/.pdr-kocum-agent/mcp-runtime");
    const python = join(runtime, "python-tools/math_core/.venv/bin/python");
    assert((await realpath(python)).startsWith(root + sep));
    const sources = (await readdir(runtime)).filter(name => /^sources-[a-f0-9]+$/u.test(name));
    assert.equal(sources.length, 1);
    const cwd = join(runtime, sources[0], "assets/mcp/math_core");
    assert((await realpath(cwd)).startsWith(root + sep));
    output.workerSHA256 = createHash("sha256").update(await readFile(join(cwd, "lgs_math/worker.py"))).digest("hex");
    const env = { PATH: "/usr/bin:/bin", HOME: join(root, "home"), LANG: "en_US.UTF-8",
        TMPDIR: join(root, "tmp"), MPLBACKEND: "Agg", OPENBLAS_NUM_THREADS: "1", OMP_NUM_THREADS: "1" };
    const probe = (name, args, input) => {
        const child = spawnSync(python, args, { cwd, env, input, encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 });
        output.probes.push({ name, status: child.status, signal: child.signal,
            error: child.error?.message, stdout: child.stdout, stderr: child.stderr });
    };
    probe("actual bounded worker and synthetic equation", ["-m", "lgs_math.worker", "solve_equation"],
        JSON.stringify({ left: "2*x+3", right: "11", variable: "x", expected: "4" }));
    probe("stdlib resource setup with the same production limits", ["-c", `
import json,os,platform,resource,subprocess,sys
print(json.dumps({'python':sys.version,'machine':platform.machine(),'RLIMIT_AS':resource.getrlimit(resource.RLIMIT_AS),'vszKiB':subprocess.check_output(['/bin/ps','-o','vsz=','-p',str(os.getpid())],text=True).strip()}),flush=True)
from lgs_math.worker import set_resource_limits
set_resource_limits('solve_equation')
print('Production resource setup completed',flush=True)
import pydantic,sympy
print('Bounded dependency imports completed',flush=True)
`]);
    probe("dependency import baseline only; no math tool execution", ["-c", "import pydantic,sympy;print(pydantic.__version__,sympy.__version__)"]);
} catch (error) { output.error = String(error); }
await writeFile(join(root, "math-worker-diagnostic.json"), JSON.stringify(output, null, 2) + "\n");
console.log(JSON.stringify(output));
