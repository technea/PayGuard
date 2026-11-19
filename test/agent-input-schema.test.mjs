import test from "node:test";
import assert from "node:assert/strict";
import {
  AGENT_INPUT_SCHEMA,
  AGENT_INPUT_SCHEMA_VERSION,
  validateAgentInput
} from "../src/agent/input-schema.mjs";
import { runPayGuardAgent } from "../src/agent/core-agent.mjs";
import {
  createPayGuardAgentMcpPlugin,
  PAYGUARD_CORE_AGENT_TOOL
} from "../src/agent/mcp.mjs";

const URL = "https://example.org";

function validInput(overrides = {}) {
  return {
    schemaVersion: AGENT_INPUT_SCHEMA_VERSION,
    requestId: "req-test-001",
    network: { name: "base", chainId: 8453 },
    target: { type: "URL", value: URL },
    context: { source: "USER", userIntent: "Verify this URL before trusting it." },
    checks: [{
      toolName: "payguard_analyze_url",
      input: { url: URL },
      checkId: "url-check",
      required: true
    }],
    constraints: {
      readOnly: true,
      maxToolCalls: 1,
      maxExecutionTimeMs: 5000,
      maxConcurrency: 1,
      perToolTimeoutMs: 2000
    },
    ...overrides
  };
}

function fakePlugin() {
  const calls = [];
  return {
    calls,
    tools: [],
    invokeTool(name, input) {
      calls.push({ name, input });
      return { verdict: "EXPECTED_DOMAIN_MATCH", checks: [] };
    }
  };
}

test("Core Agent schema declares Draft 2020-12 and rejects additional root properties", () => {
  assert.equal(AGENT_INPUT_SCHEMA.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(AGENT_INPUT_SCHEMA.additionalProperties, false);
  assert.throws(() => validateAgentInput({ ...validInput(), unexpected: true }), /unsupported property/);
});

test("Core Agent accepts a valid versioned Base request and returns a defensive JSON clone", () => {
  const input = validInput();
  const validated = validateAgentInput(input);
  assert.deepEqual(validated, input);
  assert.notEqual(validated, input);
  assert.notEqual(validated.checks, input.checks);
});

test("Core Agent rejects non-JSON values instead of silently coercing them", () => {
  assert.throws(() => validateAgentInput(validInput({
    context: { userIntent: undefined }
  })), /undefined field/);
});

test("Core Agent rejects unsupported schema versions, unknown nested fields, and mismatched networks", () => {
  assert.throws(() => validateAgentInput(validInput({ schemaVersion: "2.0.0" })), /schemaVersion/);
  assert.throws(() => validateAgentInput(validInput({
    target: { type: "URL", value: URL, extra: true }
  })), /unsupported property/);
  assert.throws(() => validateAgentInput(validInput({
    network: { name: "base", chainId: 84532 }
  })), /matching chainId/);
});

test("Core Agent rejects malformed target values and non-allowlisted tools", () => {
  assert.throws(() => validateAgentInput(validInput({
    target: { type: "WALLET_ADDRESS", value: "0x1234" }
  })), /20-byte EVM addresses/);
  assert.throws(() => validateAgentInput(validInput({
    checks: [{ toolName: "arbitrary_external_tool", input: {} }]
  })), /not allowlisted/);
});

test("Core Agent rejects unsafe or excessive execution constraints before tool invocation", () => {
  assert.throws(() => validateAgentInput(validInput({
    constraints: { readOnly: false, maxToolCalls: 1, maxExecutionTimeMs: 5000 }
  })), /read-only/);
  assert.throws(() => validateAgentInput(validInput({
    constraints: { readOnly: true, maxToolCalls: 0, maxExecutionTimeMs: 5000 }
  })), /maxToolCalls/);
  assert.throws(() => validateAgentInput(validInput({
    checks: [
      { toolName: "payguard_analyze_url", input: {} },
      { toolName: "payguard_check_address_security", input: {} }
    ]
  })), /maxToolCalls/);
});

test("Core Agent delegates to bounded investigation and preserves Evidence Core as final decision authority", async () => {
  const targetPlugin = fakePlugin();
  const result = await runPayGuardAgent(validInput(), { targetPlugin });
  assert.equal(targetPlugin.calls.length, 1);
  assert.equal(targetPlugin.calls[0].name, "payguard_analyze_url");
  assert.equal(result.agentRequest.requestId, "req-test-001");
  assert.equal(result.execution.mode, "EXPLICIT_PLAN");
  assert.equal(result.assessment.overallStatus, "VERIFIED");
  assert.equal(result.assessment.decision, "ALLOW");
  assert.equal(result.assessment.confidence, 1);
});

test("invalid Core Agent input is rejected before any security tool is invoked", async () => {
  const targetPlugin = fakePlugin();
  await assert.rejects(
    runPayGuardAgent(validInput({ constraints: {
      readOnly: false,
      maxToolCalls: 1,
      maxExecutionTimeMs: 5000
    } }), { targetPlugin }),
    /read-only/
  );
  assert.equal(targetPlugin.calls.length, 0);
});

test("MCP exposes the strict Core Agent schema as a separate tool", async () => {
  const targetPlugin = fakePlugin();
  const agentPlugin = createPayGuardAgentMcpPlugin({ targetPlugin });
  assert.equal(agentPlugin.tools.length, 2);
  assert.equal(PAYGUARD_CORE_AGENT_TOOL.name, "payguard_run_agent");
  assert.equal(PAYGUARD_CORE_AGENT_TOOL.inputSchema, AGENT_INPUT_SCHEMA);
  const result = await agentPlugin.invokeTool("payguard_run_agent", validInput());
  assert.equal(result.agentRequest.requestId, "req-test-001");
  assert.equal(result.assessment.decision, "ALLOW");
});
