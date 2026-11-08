import { createServer } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdir, cp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createReadStream } from "node:fs";
import { join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import {
    gymRunPathsCreate,
    gymRunClean,
} from "../packages/happy-desktop-gym/sources/electron/paths.ts";
import { happyAgentRuntimeCreate } from "../packages/happy-desktop-gym/sources/electron/happyAgentRuntime.ts";
import { happyAgentClientCreate } from "../packages/happy-desktop-gym/sources/electron/happyAgentProtocol.ts";
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const out = resolve(
    process.env.CYBERFI_ROLE_QA_REPORT ?? ".context/cyberfi-released-role-qa-report.json",
);
const report: any = {
    platform: process.platform,
    executable: process.env.HAPPY_DESKTOP_AGENT_EXECUTABLE,
    permissionMode: "read_only",
    paidModels: false,
    requests: [],
    roleReads: [],
    inferenceCalls: 0,
};
process.env.TMPDIR = await realpath(tmpdir());
const { paths } = await gymRunPathsCreate("smoke");
report.isolatedRoot = paths.root;
const skillRoot = join(paths.home, ".agents", "skills");
const expected = new Map<string, string>();
try {
// Read only role data already shipped in the independently verified public DMG.
const resources = process.env.CYBERFI_RELEASED_RESOURCES;
assert.ok(resources, "Pinned released DMG resources are required");
const archive = JSON.parse(
    gunzipSync(await readFile(join(resources, "pdr-catalog", "cyberfi-catalog.json.gz")), { maxOutputLength: 24 * 1024 * 1024 }).toString("utf8"),
);
for (const [path, encoded] of Object.entries(archive))
    if (/^pdrkocum-ai-agent-[^/]+\/SKILL\.md$/.test(path))
        expected.set(
            path.split("/")[0]!,
            Buffer.from(encoded as string, "base64").toString("utf8"),
        );
for (const name of [
    "pdr-yonetici",
    "pdr-arastirmaci",
    "pdr-gelistirici",
    "pdr-tasarimci",
    "pdr-kontrolcu",
    "pdr-icerik-uzmani",
])
    expected.set(name, await readFile(join(resources, "pdr-skills", name, "SKILL.md"), "utf8"));
report.expectedRoles = expected.size;
if (expected.size !== 490) throw Error("Expected exactly 490 shipped role definitions");
await cp(join(resources, "pdr-skills"), skillRoot, { recursive: true, errorOnExist: true });
for (const [relative, encoded] of Object.entries(archive)) {
    const parts = relative.split("/");
    assert.ok(parts.length > 1 && parts.every(part => part !== "" && part !== "." && part !== ".." && !part.includes("\\") && !part.includes(":")));
    assert.equal(typeof encoded, "string");
    await mkdir(join(skillRoot, ...parts.slice(0, -1)), { recursive: true });
    await writeFile(join(skillRoot, ...parts), Buffer.from(encoded as string, "base64"), { flag: "wx" });
}
} catch (error) {
    report.fatal = String(error);
    await writeFile(out, JSON.stringify(report, null, 2));
    await gymRunClean(paths.root);
    throw error;
}
let childReadEmitted = new Set<string>();
const emittedBatches = new Set<string>();
const modelReceipts = new Map<string, any>();
const server = createServer(async (req, res) => {
    try {
        const chunks = [];
        for await (const part of req) chunks.push(part);
        const input = JSON.parse(Buffer.concat(chunks).toString());
        report.inferenceCalls++;
        const userText = JSON.stringify(input.context?.messages ?? input.messages ?? []);
        const sessionKey = input.options?.sessionId ?? "unknown";
        const messages = input.context?.messages ?? input.messages ?? [];
        const calls = new Map<string, any>();
        for (const message of messages) for (const block of message.content ?? []) {
            if (block.type === "tool_call" && block.name === "read_skill") {
                let args = block.arguments;
                if (typeof args === "string") { try { args = JSON.parse(args); } catch {} }
                calls.set(block.callId, args);
            }
        }
        const capture = (result: any) => {
            const name = calls.get(result.callId)?.name;
            if (!name || !expected.has(name)) return;
            const key = sessionKey + ":" + result.callId;
            if (modelReceipts.has(key)) return;
            const text = (result.content ?? []).filter((block: any) => block.type === "text").map((block: any) => block.text).join("");
            const expectedSha256 = sha(expected.get(name)!);
            modelReceipts.set(key, { sessionKey, callId: result.callId, name, characters: text.length, expectedCharacters: expected.get(name)!.length, expectedSha256, actualSha256: sha(text), isError: Boolean(result.isError), exact: !result.isError && sha(text) === expectedSha256 });
        };
        for (const message of messages) {
            if (message.role === "tool") capture(message);
            for (const block of message.content ?? []) if (block.type === "tool_result") capture(block);
        }
        report.modelInputReceipts = [...modelReceipts.values()];
        let content: any[] = [
            { type: "text", text: "Local deterministic role access audit complete." },
        ];
        const batchMarker = [...userText.matchAll(/QA_BATCH:([A-Za-z0-9+/=]+)/g)].at(-1)?.[1];
        const batchKey = sessionKey + ":" + batchMarker;
        if (
            batchMarker &&
            !String(sessionKey).includes("naming") &&
            !emittedBatches.has(batchKey)
        ) {
            emittedBatches.add(batchKey);
            const tools = JSON.parse(Buffer.from(batchMarker, "base64").toString("utf8"));
            content = tools.map((tool: any) => ({ type: "toolCall", ...tool }));
        } else if (
            userText.includes("CHILD_READ_ONE") &&
            !userText.includes("create_agent") &&
            !childReadEmitted.has(sessionKey)
        ) {
            childReadEmitted.add(sessionKey);
            content = [
                { type: "toolCall", name: "read_skill", arguments: { name: "pdr-kontrolcu" } },
            ];
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ content, completionDelayMs: 1 }));
    } catch {
        res.writeHead(500).end();
    }
});
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
let runtime: any;
const persist = async () => writeFile(out, JSON.stringify(report, null, 2));
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
try {
    const binaryHash = createHash("sha256");
    for await (const chunk of createReadStream(report.executable)) binaryHash.update(chunk);
    report.binarySha256 = binaryHash.digest("hex");
    if (process.env.CYBERFI_ROLE_QA_BINARY_SHA256 && report.binarySha256 !== process.env.CYBERFI_ROLE_QA_BINARY_SHA256) throw Error("Pinned released engine binary SHA256 mismatch");
    runtime = await happyAgentRuntimeCreate(paths, {
        url: `http://127.0.0.1:${(server.address() as any).port}/inference`,
        token: randomBytes(24).toString("hex"),
        start: async () => {},
        stop: async () => {},
    });
    const api: any = happyAgentClientCreate(runtime.socketPath, runtime.token);
    report.health = await api.getHealth();
    const catalog = [];
    let pageCursor: string | undefined;
    do {
        const page = await api.listGlobalSkills({
            limit: 100,
            ...(pageCursor ? { pageCursor } : {}),
        });
        catalog.push(...page.skills);
        pageCursor = page.nextPageCursor ?? undefined;
    } while (pageCursor);
    report.registeredRoleCount = catalog.filter((entry: any) => expected.has(entry.name)).length;
    report.registeredRoleStatus = catalog
        .filter((entry: any) => expected.has(entry.name))
        .map((entry: any) => ({ name: entry.name, status: entry.status, enabled: entry.enabled }));
    const { bot } = await api.createBot({ name: "Isolated role read acceptance" });
    report.parentAgentId = bot.agent.id;
    const request = async (agentId: string, tools: any[], label: string) => {
        const id = `q${randomUUID().replaceAll("-", "").slice(0, 23)}`;
        const batchMarker =
            tools.length > 1
                ? " QA_BATCH:" + Buffer.from(JSON.stringify(tools)).toString("base64")
                : "";
        await api.sendMessage(agentId, {
            id,
            text: "Run isolated read-only acceptance " + label + batchMarker,
            delivery: "queue",
            ...(tools.length === 1
                ? { content: tools.map((tool) => ({ type: "tool_call_request", ...tool })) }
                : {}),
            mode: {
                providerId: "gym",
                modelId: "openai/gym",
                effort: "off",
                permissionMode: "read_only",
                serviceTier: null,
            },
        });
        for (let tries = 0; tries < 300; tries++) {
            const history = await api.getMessages(agentId, { limit: 100 });
            const run = history.runs.find((run: any) =>
                run.messages.some((message: any) => message.id === id),
            );
            if (run && ["completed", "failed", "stopped"].includes(run.status))
                return run.messages
                    .flatMap((message: any) => message.content)
                    .filter((block: any) => block.type === "tool_call");
            await delay(100);
        }
        throw Error("Timed out waiting for " + label);
    };
    const listed = await request(
        bot.agent.id,
        [{ name: "list_skills", arguments: { query: "pdr", limit: 256 } }],
        "list_skills",
    );
    report.listSkills = listed.map((tool: any) => ({
        name: tool.name,
        status: tool.status,
        result: tool.result,
    }));
    const names = [...expected.keys()]
        .sort()
        .slice(0, Number(process.env.CYBERFI_ROLE_QA_LIMIT ?? expected.size));
    const batchSize = Number(process.env.CYBERFI_ROLE_QA_BATCH_SIZE ?? 8);
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 8)
        throw Error("Invalid bounded batch size");
    for (let offset = 0; offset < names.length; offset += batchSize) {
        const batch = names.slice(offset, offset + batchSize);
        // Independent bounded contexts prevent re-tokenizing hundreds of prior full role bodies.
        const batchAgent = (await api.createBot({ name: `Read-only role batch ${offset / batchSize + 1}` })).bot.agent.id;
        const tools = await request(
            batchAgent,
            batch.map((name) => ({ name: "read_skill", arguments: { name } })),
            `roles ${offset + 1}-${offset + batch.length}`,
        );
        for (const name of batch) {
            const tool = tools.find(
                (tool: any) => tool.name === "read_skill" && tool.arguments?.name === name,
            );
            let result = tool?.result;
            if (typeof result === "string") {
                try {
                    result = JSON.parse(result);
                } catch {}
            }
            const content = result?.content ?? result?.output;
            const expectedSha256 = sha(expected.get(name)!);
            const modelReceipt = [...modelReceipts.values()].find((receipt: any) => receipt.name === name);
            const actualSha256 = modelReceipt?.actualSha256;
            report.roleReads.push({
                name,
                status: tool?.status ?? "missing",
                exact: tool?.status === "completed" && modelReceipt?.exact === true,
                modelReceipt,
                historyTruncated: typeof content === "string" && content.includes("...[truncated "),
                expectedSha256,
                actualSha256,
                ...(actualSha256 === expectedSha256
                    ? {}
                    : { error: JSON.stringify(result ?? tool).slice(0, 1200) }),
            });
        }
        await persist();
        if (
            report.roleReads.length === batchSize ||
            report.roleReads.length % 40 === 0 ||
            report.roleReads.length === names.length
        )
            console.log(
                JSON.stringify({
                    progress: report.roleReads.length,
                    total: names.length,
                    exact: report.roleReads.filter((read: any) => read.exact).length,
                    firstError: report.roleReads.find((read: any) => !read.exact)?.error,
                }),
            );
    }
    const created = await request(
        bot.agent.id,
        [
            {
                name: "create_agent",
                arguments: {
                    title: "Read-only role access child",
                    model: "openai/gym",
                    provider: "gym",
                    effort: "off",
                    read_only: true,
                    text: "CHILD_READ_ONE Read pdr-kontrolcu with read_skill. No file changes, no other agents.",
                },
            },
        ],
        "create read-only child",
    );
    report.childCreation = created.map((tool: any) => ({
        name: tool.name,
        status: tool.status,
        result: tool.result,
    }));
    let createdResult: any = created.find((tool: any) => tool.name === "create_agent")?.result;
    if (typeof createdResult === "string") {
        try {
            createdResult = JSON.parse(createdResult);
        } catch {}
    }
    if (!createdResult?.agentId && typeof createdResult?.output === "string") {
        const found = /Created collaborator ([a-z0-9]+)/.exec(createdResult.output);
        if (found) createdResult.agentId = found[1];
    }
    if (createdResult?.agentId) {
        report.childAgentId = createdResult.agentId;
        for (let tries = 0; tries < 300; tries++) {
            const history = await api.getMessages(createdResult.agentId, { limit: 100 });
            const read = history.runs
                .flatMap((run: any) => run.messages)
                .flatMap((message: any) => message.content)
                .find((block: any) => block.type === "tool_call" && block.name === "read_skill");
            if (read && read.status !== "running") {
                report.childRead = {
                    id: read.id,
                    status: read.status,
                    arguments: read.arguments,
                    result: read.result,
                };
                break;
            }
            await delay(100);
        }
        report.childState = (await api.getAgent(createdResult.agentId)).agent;
    }
    report.exactReadCount = report.roleReads.filter((read: any) => read.exact).length;
    let childResult = report.childRead?.result;
    if (typeof childResult === "string") {
        try {
            childResult = JSON.parse(childResult);
        } catch {}
    }
    const childContent = childResult?.content ?? childResult?.output;
    // A tool may finish before the next provider call. Session ids are not agent ids.
    let childReceipt: any;
    for (let attempt = 0; attempt < 300; attempt++) {
        childReceipt = [...modelReceipts.values()].find((receipt: any) => receipt.name === "pdr-kontrolcu" && childReadEmitted.has(receipt.sessionKey));
        if (childReceipt) break;
        await delay(100);
    }
    report.childProviderSessions = [...childReadEmitted];
    report.childModelInputReceipt = childReceipt;
    report.childExact = report.childRead?.status === "completed" && childReceipt?.exact === true;
    report.limits = ["These are real read_skill access/body-delivery checks under read_only, not490semantic specialist model tasks.", "All inference is a local deterministic provider; no paid account/vendor request.", "History tool output may be intentionally truncated at16000characters; exact hashes use actual provider input text.", "Support-file shell and private-read denial are separate native engine gate checks, not inferred from this role-body sweep."];
    report.success =
        report.registeredRoleCount === 490 &&
        report.roleReads.length === 490 &&
        report.exactReadCount === 490 &&
        report.childExact;
    if (!report.success) process.exitCode = 1;
} catch (error) {
    report.fatal = String(error);
    process.exitCode = 1;
    console.log(JSON.stringify({ fatal: report.fatal }));
} finally {
    await runtime?.stop();
    server.close();
    await persist();
    await gymRunClean(paths.root);
}
