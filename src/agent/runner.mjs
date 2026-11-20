/**
 * @module agent/runner
 * @section Bounded deterministic tool orchestration
 * Executes an explicit, caller-supplied plan with fixed concurrency and time budgets.
 * It does not plan, discover, chain, or authorize tools autonomously.
 */
import { MAX_EVIDENCE_RECORDS } from "./constants.mjs";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";
import { cloneJsonValue } from "./canonical-json.mjs";
import { normalizeToolResult } from "./normalize-result.mjs";
import { createErrorEvidence, createNotCheckedEvidence } from "./evidence-record.mjs";
import { buildEvidenceReport } from "./report.mjs";

const MAX_CONCURRENCY = 3;
const DEFAULT_CONCURRENCY = 3;
const DEFAULT_PER_TOOL_TIMEOUT_MS = 6_000;
const DEFAULT_TOTAL_TIMEOUT_MS = 15_000;
const MAX_PER_TOOL_TIMEOUT_MS = 15_000;
const MAX_TOTAL_TIMEOUT_MS = 30_000;

function requireIntegerInRange(value, name, min, max, fallback) {
  const resolved = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new RangeError(name + " must be an integer between " + min + " and " + max + ".");
  }
  return resolved;
}

function validatePlan(checks, executeTool) {
  if (!Array.isArray(checks) || checks.length === 0) {
    throw new TypeError("An investigation requires at least one explicit check.");
  }
  if (checks.length > MAX_EVIDENCE_RECORDS) {
    throw new RangeError("Investigation exceeds the evidence record limit.");
  }
  if (typeof executeTool !== "function") {
    throw new TypeError("executeTool must be a function supplied by the trusted host.");
  }

  const seen = new Set();
  return checks.map((check, index) => {
    if (!check || typeof check !== "object" || Array.isArray(check)) {
      throw new TypeError("Each check must be an object.");
    }
    const toolName = check.toolName;
    if (!isKnownPayGuardTool(toolName)) {
      throw new TypeError("Unknown PayGuard tool in check " + index + ".");
    }
    if (seen.has(toolName)) {
      throw new TypeError("Duplicate tool checks are not allowed: " + toolName + ".");
    }
    seen.add(toolName);
    const input = check.input === undefined ? {} : check.input;
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError("Tool input must be a JSON object for " + toolName + ".");
    }
    return {
      toolName,
      input: cloneJsonValue(input),
      checkId: typeof check.checkId === "string" && check.checkId.trim() ? check.checkId.slice(0, 120) : toolName,
      required: check.required !== false
    };
  });
}

/**
 * Validate and execute planner tool calls in dependency order.
 *
 * A call is dispatchable only after every declared dependency has resolved.
 * A rejected dispatch marks that call FAILED and all downstream dependants BLOCKED.
 * Independent calls continue, subject to the fixed concurrency cap.
 *
 * dispatchToolCall is supplied by the trusted host and remains responsible for
 * translating the validated planner call into the existing tool's input contract.
 * This scheduler does not discover tools, interpret evidence verdicts, or authorize
 * transactions.
 */
export async function runDependentToolCalls({
  toolCalls,
  dispatchToolCall,
  maxConcurrency = DEFAULT_CONCURRENCY
} = {}) {
  if (!Array.isArray(toolCalls)) {
    throw new TypeError("toolCalls must be an array.");
  }
  if (toolCalls.length === 0) return [];
  if (toolCalls.length > 7) {
    throw new RangeError("Planner output exceeds the seven-call execution limit.");
  }
  if (typeof dispatchToolCall !== "function") {
    throw new TypeError("dispatchToolCall must be a function supplied by the trusted host.");
  }
  const concurrency = requireIntegerInRange(
    maxConcurrency,
    "maxConcurrency",
    1,
    MAX_CONCURRENCY,
    DEFAULT_CONCURRENCY
  );

  const calls = toolCalls.map((call, index) => {
    if (!call || typeof call !== "object" || Array.isArray(call)) {
      throw new TypeError("Each planner tool call must be an object.");
    }
    if (typeof call.callId !== "string" || !call.callId.trim()) {
      throw new TypeError("Each planner tool call requires a non-empty callId.");
    }
    if (!isKnownPayGuardTool(call.toolName)) {
      throw new TypeError("Unknown PayGuard tool in planner call " + index + ".");
    }
    const dependencies = call.dependsOn === undefined ? [] : call.dependsOn;
    if (!Array.isArray(dependencies) || dependencies.some(id => typeof id !== "string" || !id.trim())) {
      throw new TypeError("dependsOn must contain non-empty callId strings.");
    }
    if (new Set(dependencies).size !== dependencies.length) {
      throw new TypeError("Duplicate dependencies are not allowed for " + call.callId + ".");
    }
    return { call: cloneJsonValue(call), index, dependencies: [...dependencies] };
  });

  const byId = new Map();
  for (const item of calls) {
    if (byId.has(item.call.callId)) {
      throw new TypeError("Duplicate planner callId: " + item.call.callId + ".");
    }
    byId.set(item.call.callId, item);
  }

  for (const item of calls) {
    for (const dependencyId of item.dependencies) {
      if (dependencyId === item.call.callId) {
        throw new TypeError("A planner call cannot depend on itself: " + dependencyId + ".");
      }
      if (!byId.has(dependencyId)) {
        throw new TypeError("Unknown dependency " + dependencyId + " for " + item.call.callId + ".");
      }
    }
  }

  // Reject cycles before any tool is dispatched.
  const indegree = new Map(calls.map(item => [item.call.callId, item.dependencies.length]));
  const dependants = new Map(calls.map(item => [item.call.callId, []]));
  for (const item of calls) {
    for (const dependencyId of item.dependencies) {
      dependants.get(dependencyId).push(item.call.callId);
    }
  }
  const readyForCycleCheck = calls
    .filter(item => indegree.get(item.call.callId) === 0)
    .map(item => item.call.callId);
  let visited = 0;
  while (readyForCycleCheck.length > 0) {
    const callId = readyForCycleCheck.shift();
    visited++;
    for (const dependantId of dependants.get(callId)) {
      const nextDegree = indegree.get(dependantId) - 1;
      indegree.set(dependantId, nextDegree);
      if (nextDegree === 0) readyForCycleCheck.push(dependantId);
    }
  }
  if (visited !== calls.length) {
    throw new TypeError("Planner tool-call dependencies contain a cycle.");
  }

  const states = new Map(calls.map(item => [item.call.callId, {
    status: "PENDING",
    result: undefined,
    error: undefined
  }]));
  const results = new Array(calls.length);
  let pendingCount = calls.length;

  while (pendingCount > 0) {
    let changed = false;

    // A failed prerequisite blocks dependants without dispatching them.
    for (const item of calls) {
      const state = states.get(item.call.callId);
      if (state.status !== "PENDING") continue;
      const failedDependency = item.dependencies.find(id => {
        const dependencyStatus = states.get(id).status;
        return dependencyStatus === "FAILED" || dependencyStatus === "BLOCKED";
      });
      if (failedDependency) {
        state.status = "BLOCKED";
        state.error = "Dependency " + failedDependency + " did not complete successfully.";
        results[item.index] = {
          callId: item.call.callId,
          toolName: item.call.toolName,
          status: "BLOCKED",
          evidenceStatus: "NOT_CHECKED",
          reason: "This step was skipped because a dependency did not complete.",
          blockedBy: failedDependency
        };
        pendingCount--;
        changed = true;
      }
    }

    const ready = calls.filter(item => {
      if (states.get(item.call.callId).status !== "PENDING") return false;
      return item.dependencies.every(id => states.get(id).status === "COMPLETED");
    });

    if (ready.length === 0) {
      if (!changed && pendingCount > 0) {
        throw new Error("Dependency scheduler reached an invalid non-progress state.");
      }
      continue;
    }

    const batch = ready.slice(0, concurrency);
    await Promise.all(batch.map(async item => {
      const state = states.get(item.call.callId);
      state.status = "RUNNING";
      try {
        const dependencyResults = Object.fromEntries(
          item.dependencies.map(id => [id, states.get(id).result])
        );
        const result = await dispatchToolCall(cloneJsonValue(item.call), dependencyResults);
        state.status = "COMPLETED";
        state.result = result;
        results[item.index] = {
          callId: item.call.callId,
          toolName: item.call.toolName,
          status: "COMPLETED",
          result
        };
      } catch (error) {
        state.status = "FAILED";
        state.error = error;
        results[item.index] = {
          callId: item.call.callId,
          toolName: item.call.toolName,
          status: "FAILED",
          evidenceStatus: "ERROR",
          errorCode: "TOOL_DISPATCH_FAILED",
          error: error instanceof Error ? error.message : "Tool dispatch failed."
        };
      }
      pendingCount--;
    }));
  }

  return results;
}

function raceWithTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  return Promise.race([
    Promise.resolve(promise).then(value => ({ value }), error => ({ rejected: true, error })),
    timeout
  ]).finally(() => clearTimeout(timer));
}

async function executeCheck(check, executeTool, timeoutMs) {
  const startedAt = new Date().toISOString();
  const started = Date.now();
  try {
    const pending = executeTool(check.toolName, cloneJsonValue(check.input));
    const outcome = await raceWithTimeout(pending, timeoutMs);
    const durationMs = Math.max(0, Date.now() - started);
    const completedAt = new Date().toISOString();

    if (outcome.timedOut) {
      return createErrorEvidence(check.toolName, new Error("Tool timeout"), {
        checkId: check.checkId,
        required: check.required,
        startedAt,
        completedAt,
        durationMs,
        errorCode: "TOOL_TIMEOUT"
      });
    }
    if (outcome.rejected) {
      return createErrorEvidence(check.toolName, outcome.error, {
        checkId: check.checkId,
        required: check.required,
        startedAt,
        completedAt,
        durationMs,
        errorCode: "TOOL_EXECUTION_FAILED"
      });
    }
    return normalizeToolResult(check.toolName, outcome.value, {
      checkId: check.checkId,
      required: check.required,
      startedAt,
      completedAt,
      durationMs
    });
  } catch (error) {
    return createErrorEvidence(check.toolName, error, {
      checkId: check.checkId,
      required: check.required,
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Math.max(0, Date.now() - started),
      errorCode: "TOOL_EXECUTION_FAILED"
    });
  }
}

/**
 * Run an explicit set of existing read-only PayGuard tools.
 * Tool execution is injected by the trusted caller; this module has no network access.
 * Timed-out work is not cancelled, so executors must remain read-only and late results
 * are discarded. The runner never signs, broadcasts, or executes transactions.
 */
export async function runInvestigation({
  subject = null,
  checks,
  executeTool,
  options = {}
} = {}) {
  const plan = validatePlan(checks, executeTool);
  const maxConcurrency = requireIntegerInRange(options.maxConcurrency, "maxConcurrency", 1, MAX_CONCURRENCY, DEFAULT_CONCURRENCY);
  const perToolTimeoutMs = requireIntegerInRange(options.perToolTimeoutMs, "perToolTimeoutMs", 1, MAX_PER_TOOL_TIMEOUT_MS, DEFAULT_PER_TOOL_TIMEOUT_MS);
  const totalTimeoutMs = requireIntegerInRange(options.totalTimeoutMs, "totalTimeoutMs", 1, MAX_TOTAL_TIMEOUT_MS, DEFAULT_TOTAL_TIMEOUT_MS);

  const started = Date.now();
  const deadline = started + totalTimeoutMs;
  const records = new Array(plan.length);
  let cursor = 0;

  async function worker() {
    while (true) {
      const index = cursor++;
      if (index >= plan.length) return;
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        records[index] = createNotCheckedEvidence(plan[index].toolName, {
          checkId: plan[index].checkId,
          required: plan[index].required,
          reason: "The total investigation time budget expired before this check started."
        });
        continue;
      }
      records[index] = await executeCheck(plan[index], executeTool, Math.min(perToolTimeoutMs, remainingMs));
    }
  }

  await Promise.all(Array.from({ length: Math.min(maxConcurrency, plan.length) }, () => worker()));

  const completedAt = new Date().toISOString();
  const report = buildEvidenceReport(subject, records, {
    investigationId: "investigation:" + started
  });
  return {
    ...report,
    execution: {
      mode: "EXPLICIT_PLAN",
      plannedChecks: plan.length,
      maxConcurrency,
      perToolTimeoutMs,
      totalTimeoutMs,
      durationMs: Math.max(0, Date.now() - started),
      startedAt: new Date(started).toISOString(),
      completedAt,
      timedOutChecks: records.filter(record => record?.errorCode === "TOOL_TIMEOUT").length,
      notStartedChecks: records.filter(record => record?.status === "NOT_CHECKED").length,
      lateResultsCancelled: false
    }
  };
}
