import test from "node:test";
import assert from "node:assert/strict";
import { runDependentToolCalls } from "../src/agent/runner.mjs";

const call = (callId, toolName, dependsOn) => ({
  callId,
  toolName,
  purpose: "domain_reputation",
  priority: 1,
  targetRef: "https://example.com",
  ...(dependsOn ? { dependsOn } : {})
});

test("dispatches dependent calls only after prerequisites complete", async () => {
  const order = [];
  const result = await runDependentToolCalls({
    toolCalls: [
      call("second", "payguard_check_address_security", ["first"]),
      call("first", "payguard_analyze_url")
    ],
    dispatchToolCall: async item => {
      order.push(item.callId);
      return { completedCall: item.callId };
    }
  });

  assert.deepEqual(order, ["first", "second"]);
  assert.deepEqual(result.map(item => item.status), ["COMPLETED", "COMPLETED"]);
});

test("passes completed dependency results to the dependent dispatch", async () => {
  let received;
  await runDependentToolCalls({
    toolCalls: [
      call("first", "payguard_analyze_url"),
      call("second", "payguard_check_address_security", ["first"])
    ],
    dispatchToolCall: async item => {
      if (item.callId === "first") return { reference: "resolved-domain" };
      received = item;
      return { ok: true };
    }
  });

  assert.equal(received.callId, "second");
});

test("blocks dependants when a prerequisite dispatch fails", async () => {
  const dispatched = [];
  const result = await runDependentToolCalls({
    toolCalls: [
      call("root", "payguard_analyze_url"),
      call("child", "payguard_check_address_security", ["root"]),
      call("independent", "payguard_check_token_security")
    ],
    dispatchToolCall: async item => {
      dispatched.push(item.callId);
      if (item.callId === "root") throw new Error("upstream unavailable");
      return { ok: true };
    }
  });

  assert.deepEqual(dispatched.sort(), ["independent", "root"]);
  assert.equal(result[0].status, "FAILED");
  assert.equal(result[1].status, "BLOCKED");
  assert.equal(result[1].blockedBy, "root");
  assert.equal(result[2].status, "COMPLETED");
});

test("rejects duplicate call IDs before dispatch", async () => {
  let dispatches = 0;
  await assert.rejects(runDependentToolCalls({
    toolCalls: [
      call("same", "payguard_analyze_url"),
      call("same", "payguard_check_token_security")
    ],
    dispatchToolCall: async () => { dispatches++; }
  }), /Duplicate planner callId/);
  assert.equal(dispatches, 0);
});

test("rejects missing dependencies before dispatch", async () => {
  let dispatches = 0;
  await assert.rejects(runDependentToolCalls({
    toolCalls: [call("child", "payguard_analyze_url", ["missing"])],
    dispatchToolCall: async () => { dispatches++; }
  }), /Unknown dependency/);
  assert.equal(dispatches, 0);
});

test("rejects self-dependencies and cycles before dispatch", async () => {
  let dispatches = 0;
  const dispatchToolCall = async () => { dispatches++; };

  await assert.rejects(runDependentToolCalls({
    toolCalls: [call("self", "payguard_analyze_url", ["self"])],
    dispatchToolCall
  }), /cannot depend on itself/);

  await assert.rejects(runDependentToolCalls({
    toolCalls: [
      call("a", "payguard_analyze_url", ["b"]),
      call("b", "payguard_check_token_security", ["a"])
    ],
    dispatchToolCall
  }), /contain a cycle/);

  assert.equal(dispatches, 0);
});

test("enforces the existing tool allowlist and concurrency cap", async () => {
  let dispatches = 0;
  await assert.rejects(runDependentToolCalls({
    toolCalls: [call("bad", "execute_arbitrary_code")],
    dispatchToolCall: async () => { dispatches++; }
  }), /Unknown PayGuard tool/);

  await assert.rejects(runDependentToolCalls({
    toolCalls: [call("one", "payguard_analyze_url")],
    dispatchToolCall: async () => { dispatches++; },
    maxConcurrency: 4
  }), /maxConcurrency/);

  assert.equal(dispatches, 0);
});
