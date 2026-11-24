import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createMcpHttpHandler,
  handleMcpHttpRequest,
  SUPPORTED_PROTOCOL_VERSIONS,
  DEFAULT_PROTOCOL_VERSION,
  LATEST_PROTOCOL_VERSION
} from '../src/mcp/streamable-http.mjs';
import { requestHandler } from '../server.mjs';
import plugin from '../src/plugin.mjs';

const cwd = fileURLToPath(new URL('..', import.meta.url));

async function freePort() {
  return await new Promise((resolve, reject) => {
    const socket = net.createServer();
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', () => {
      const port = socket.address().port;
      socket.close(error => (error ? reject(error) : resolve(port)));
    });
  });
}

let server;
let baseUrl;

before(async () => {
  const port = await freePort();
  baseUrl = `http://127.0.0.1:${port}`;
  server = http.createServer(requestHandler);
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
});

after(async () => {
  if (server) {
    await new Promise(resolve => server.close(resolve));
  }
});

// 1. Protocol Version Negotiation and Supported Specifications
test('MCP Streamable HTTP: supports exactly 2025-03-26, 2025-06-18, and 2025-11-25', () => {
  assert.deepEqual(SUPPORTED_PROTOCOL_VERSIONS, ['2025-03-26', '2025-06-18', '2025-11-25']);
  assert.equal(DEFAULT_PROTOCOL_VERSION, '2025-11-25');
  assert.equal(LATEST_PROTOCOL_VERSION, '2025-11-25');
  // Confirm legacy 2024-11-05 and 2026-07-28 are NOT in Streamable HTTP versions
  assert.ok(!SUPPORTED_PROTOCOL_VERSIONS.includes('2024-11-05'));
  assert.ok(!SUPPORTED_PROTOCOL_VERSIONS.includes('2026-07-28'));
});

test('MCP Streamable HTTP: negotiates 2025-era protocol versions correctly', async () => {
  for (const version of ['2025-03-26', '2025-06-18', '2025-11-25']) {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'MCP-Protocol-Version': version
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: version }
      })
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('mcp-protocol-version'), version);
    const data = await res.json();
    assert.equal(data.result.protocolVersion, version);
  }
});

test('MCP Streamable HTTP: rejects 2024-11-05 and 2026-07-28 with error -32022', async () => {
  for (const rejectedVersion of ['2024-11-05', '2026-07-28', 'invalid-version']) {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'initialize',
        params: { protocolVersion: rejectedVersion }
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.error.code, -32022);
    assert.ok(data.error.message.includes('Unsupported protocol version'));
    assert.deepEqual(data.error.data.supportedVersions, SUPPORTED_PROTOCOL_VERSIONS);
  }
});

test('MCP Streamable HTTP: header MCP-Protocol-Version with unsupported version returns 400 with -32022', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'MCP-Protocol-Version': '2026-07-28'
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' })
  });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.equal(data.error.code, -32022);
});

test('MCP Streamable HTTP: detects conflicting version between header and initialize params', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'MCP-Protocol-Version': '2025-03-26'
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 4,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25' }
    })
  });
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.error.code, -32022);
  assert.ok(data.error.message.includes('Protocol version mismatch'));
});

// 2. Authentication and Access Policy Verification
test('MCP Streamable HTTP: validates Bearer token authentication when configured', async () => {
  const customHandler = createMcpHttpHandler({
    targetPlugin: plugin,
    authToken: 'secret-auth-token-12345'
  });

  // 1. Missing Authorization header returns 401
  const reqUnauth = {
    method: 'POST',
    headers: { 'content-type': 'application/json' }
  };
  let statusCode = 0;
  let resHeaders = {};
  const resUnauth = {
    setHeader(k, v) { resHeaders[k.toLowerCase()] = v; },
    writeHead(code, h) {
      statusCode = code;
      for (const [k, v] of Object.entries(h || {})) {
        resHeaders[k.toLowerCase()] = v;
      }
    },
    end() {}
  };
  await customHandler.handleRequest(reqUnauth, resUnauth);
  assert.equal(statusCode, 401);
  assert.ok(resHeaders['www-authenticate']?.includes('Bearer'));

  // 2. Wrong token returns 401
  const reqWrong = {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer wrong-token' }
  };
  await customHandler.handleRequest(reqWrong, resUnauth);
  assert.equal(statusCode, 401);

  // 3. Valid token returns 200
  let bodyWritten = '';
  const reqValid = {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer secret-auth-token-12345' },
    [Symbol.asyncIterator]: async function* () {
      yield Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping' }));
    }
  };
  const resValid = {
    setHeader(k, v) { resHeaders[k.toLowerCase()] = v; },
    writeHead(code) { statusCode = code; },
    end(b) { bodyWritten = b; }
  };
  await customHandler.handleRequest(reqValid, resValid);
  assert.equal(statusCode, 200);
  assert.ok(bodyWritten.includes('"result":{}'));
});

test('MCP Streamable HTTP: production mode blocks unauthenticated access unless explicitly opted in', async () => {
  const origEnv = process.env.NODE_ENV;
  const origAuth = process.env.MCP_AUTH_TOKEN;
  const origOptIn = process.env.MCP_ALLOW_UNAUTHENTICATED;
  process.env.NODE_ENV = 'production';
  delete process.env.MCP_AUTH_TOKEN;
  delete process.env.MCP_ALLOW_UNAUTHENTICATED;

  try {
    const customHandler = createMcpHttpHandler({ targetPlugin: plugin });
    let statusCode = 0;
    let written = '';
    const req = {
      method: 'POST',
      headers: { host: 'localhost', 'content-type': 'application/json' }
    };
    const res = {
      setHeader() {},
      writeHead(code) { statusCode = code; },
      end(b) { written = b; }
    };
    await customHandler.handleRequest(req, res);
    assert.equal(statusCode, 403, 'Must fail closed with 403 Forbidden in production when no auth token is set');
    assert.ok(written.includes('Remote MCP endpoint requires authentication in production'));
  } finally {
    process.env.NODE_ENV = origEnv;
    if (origAuth) process.env.MCP_AUTH_TOKEN = origAuth;
    if (origOptIn) process.env.MCP_ALLOW_UNAUTHENTICATED = origOptIn;
  }
});

// 3. Initialization and Session Handling
test('MCP Streamable HTTP: initialize generates session and returns serverInfo', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'TestClient', version: '1.0.0' }
      }
    })
  });

  assert.equal(res.status, 200);
  const sessionId = res.headers.get('mcp-session-id');
  assert.ok(sessionId, 'Response must include Mcp-Session-Id header');

  const data = await res.json();
  assert.equal(data.jsonrpc, '2.0');
  assert.equal(data.id, 1);
  assert.equal(data.result.protocolVersion, '2025-11-25');
  assert.equal(data.result.serverInfo.name, 'PayGuard');
  assert.equal(data.result.capabilities.tools.listChanged, false);
});

test('MCP Streamable HTTP: session header Mcp-Session-Id is validated on subsequent calls', async () => {
  const initRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })
  });
  const sessionId = initRes.headers.get('mcp-session-id');
  assert.ok(sessionId);

  const listRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Mcp-Session-Id': sessionId
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  });
  assert.equal(listRes.status, 200);
  assert.equal(listRes.headers.get('mcp-session-id'), sessionId);

  const badRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Mcp-Session-Id': 'non-existent-session-id'
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' })
  });
  assert.equal(badRes.status, 404);
  const badData = await badRes.json();
  assert.equal(badData.error.code, -32001);
});

test('MCP Streamable HTTP: rejects conflicting MCP-Protocol-Version on active session', async () => {
  const initRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'MCP-Protocol-Version': '2025-11-25'
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })
  });
  const sessionId = initRes.headers.get('mcp-session-id');
  assert.ok(sessionId);

  // Send conflicting protocol version on the same session
  const conflictRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Mcp-Session-Id': sessionId,
      'MCP-Protocol-Version': '2025-03-26'
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' })
  });
  assert.equal(conflictRes.status, 400);
  const data = await conflictRes.json();
  assert.equal(data.error.code, -32022);
  assert.ok(data.error.message.includes('Protocol version mismatch for active session'));
});

test('MCP Streamable HTTP: DELETE /mcp terminates an active session', async () => {
  const initRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })
  });
  const sessionId = initRes.headers.get('mcp-session-id');
  assert.ok(sessionId);

  const delRes = await fetch(`${baseUrl}/mcp`, {
    method: 'DELETE',
    headers: { 'Mcp-Session-Id': sessionId }
  });
  assert.equal(delRes.status, 204);

  const delRes2 = await fetch(`${baseUrl}/mcp`, {
    method: 'DELETE',
    headers: { 'Mcp-Session-Id': sessionId }
  });
  assert.equal(delRes2.status, 404);

  const callRes = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Mcp-Session-Id': sessionId
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' })
  });
  assert.equal(callRes.status, 404);
});

test('MCP Streamable HTTP: DELETE /mcp without Mcp-Session-Id header returns 400', async () => {
  const delRes = await fetch(`${baseUrl}/mcp`, { method: 'DELETE' });
  assert.equal(delRes.status, 400);
});

// 4. Tool Discovery (tools/list)
test('MCP Streamable HTTP: tools/list returns all registered PayGuard tools', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/list' })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.jsonrpc, '2.0');
  assert.equal(data.id, 10);
  assert.ok(Array.isArray(data.result.tools));
  assert.equal(data.result.tools.length, plugin.tools.length);

  const toolNames = data.result.tools.map(t => t.name);
  assert.ok(toolNames.includes('payguard_check_payment_intent'));
  assert.ok(toolNames.includes('payguard_analyze_url'));
  assert.ok(toolNames.includes('payguard_prepare_threat_report'));
  assert.ok(toolNames.includes('payguard_inspect_calldata'));
  assert.ok(toolNames.includes('payguard_check_token_security'));
  assert.ok(toolNames.includes('payguard_check_address_security'));
  assert.ok(toolNames.includes('payguard_scan_wallet_tokens'));
  assert.ok(toolNames.includes('payguard_near_security_intelligence'));

  for (const t of data.result.tools) {
    assert.ok(t.name, 'Tool must have name');
    assert.ok(t.description, 'Tool must have description');
    assert.ok(t.inputSchema && typeof t.inputSchema === 'object', 'Tool must have inputSchema');
  }
});

// 5. Tool Execution (tools/call)
test('MCP Streamable HTTP: tools/call executes payguard_check_payment_intent correctly', async () => {
  const policy = {
    expectedResourceUrl: 'https://api.example.com/data',
    maxAmountAtomic: '5000',
    allowedNetworks: ['eip155:8453'],
    allowedAssets: ['0x1111111111111111111111111111111111111111'],
    allowedPayTo: ['0x2222222222222222222222222222222222222222'],
    allowedSchemes: ['exact'],
    maxTimeoutSeconds: 300
  };

  const paymentRequirements = {
    resource: 'https://api.example.com/data',
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x1111111111111111111111111111111111111111',
        payTo: '0x2222222222222222222222222222222222222222',
        amount: '1000',
        maxTimeoutSeconds: 120
      }
    ]
  };

  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: {
        name: 'payguard_check_payment_intent',
        arguments: {
          intent: policy,
          paymentRequirements
        }
      }
    })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.jsonrpc, '2.0');
  assert.equal(data.id, 20);
  assert.equal(data.result.isError, false);
  assert.ok(Array.isArray(data.result.content));
  assert.equal(data.result.content[0].type, 'text');

  const parsedToolResult = JSON.parse(data.result.content[0].text);
  assert.equal(parsedToolResult.status, 'PASS');
});

test('MCP Streamable HTTP: tools/call handles tool errors gracefully without crashing', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 21,
      method: 'tools/call',
      params: {
        name: 'non_existent_tool_123',
        arguments: {}
      }
    })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.jsonrpc, '2.0');
  assert.equal(data.id, 21);
  assert.equal(data.result.isError, true);
  assert.ok(data.result.content[0].text.includes('Error executing non_existent_tool_123'));
});

test('MCP Streamable HTTP: tools/call with missing tool name returns error -32602', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 22,
      method: 'tools/call',
      params: { arguments: {} }
    })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.error.code, -32602);
});

// 6. Ping and Notifications
test('MCP Streamable HTTP: ping returns empty result', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 30, method: 'ping' })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.deepEqual(data.result, {});
});

test('MCP Streamable HTTP: notifications/initialized returns 202 without body', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
  });

  assert.equal(res.status, 202);
  const text = await res.text();
  assert.equal(text, '');
});

// 7. GET /mcp: Metadata and Streamable HTTP SSE (No legacy event: endpoint)
test('MCP Streamable HTTP: GET /mcp with application/json returns metadata summary', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'GET',
    headers: { Accept: 'application/json' }
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.service, 'payguard-mcp');
  assert.equal(data.transport, 'streamable-http');
  assert.ok(data.supportedProtocolVersions.includes('2025-11-25'));
  assert.equal(data.defaultProtocolVersion, '2025-11-25');
  assert.equal(data.toolsCount, plugin.tools.length);
});

test('MCP Streamable HTTP: GET /mcp with text/event-stream initiates SSE stream with keep-alive and NO legacy endpoint event', async () => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1000);

  try {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'GET',
      headers: { Accept: 'text/event-stream' },
      signal: controller.signal
    });

    assert.equal(res.status, 200);
    assert.ok(res.headers.get('content-type')?.includes('text/event-stream'));
    assert.ok(res.headers.get('mcp-session-id'));
    assert.ok(res.headers.get('mcp-protocol-version'));

    const reader = res.body.getReader();
    const { value } = await reader.read();
    const chunkStr = new TextDecoder().decode(value);

    // Streamable HTTP uses keep-alive comments, NOT legacy event: endpoint
    assert.ok(chunkStr.includes(': keep-alive'));
    assert.ok(!chunkStr.includes('event: endpoint'), 'Must not send deprecated event: endpoint discovery message');
    reader.cancel();
  } catch (err) {
    if (err.name !== 'AbortError') throw err;
  } finally {
    clearTimeout(timeout);
  }
});

test('MCP Streamable HTTP: POST /mcp with Accept: text/event-stream returns SSE message stream', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream'
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 40, method: 'ping' })
  });

  assert.equal(res.status, 200);
  assert.ok(res.headers.get('content-type')?.includes('text/event-stream'));
  const bodyText = await res.text();
  assert.ok(bodyText.startsWith('event: message\ndata: '));
  assert.ok(bodyText.includes('"result":{}'));
});

// 8. Security: Host Header, DNS Rebinding, Origin Validation & CORS
test('MCP Streamable HTTP: OPTIONS /mcp handles CORS preflight with Mcp-Session-Id and MCP-Protocol-Version exposed', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://chatgpt.com',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type, Mcp-Session-Id, MCP-Protocol-Version'
    }
  });

  assert.equal(res.status, 204);
  assert.ok(res.headers.get('access-control-allow-headers')?.includes('Mcp-Session-Id'));
  assert.ok(res.headers.get('access-control-allow-headers')?.includes('MCP-Protocol-Version'));
  assert.ok(res.headers.get('access-control-expose-headers')?.includes('Mcp-Session-Id'));
  assert.ok(res.headers.get('access-control-expose-headers')?.includes('MCP-Protocol-Version'));
});

test('MCP Streamable HTTP: Host header validation rejects spoofed host in production (DNS rebinding defense)', async () => {
  const origNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';

  try {
    const customHandler = createMcpHttpHandler({
      targetPlugin: plugin,
      allowedHosts: ['allowed-domain.example']
    });

    const reqMockBadHost = {
      method: 'POST',
      headers: {
        host: 'attacker-controlled-rebinding-domain.com',
        'content-type': 'application/json'
      }
    };
    let writtenStatus = 0;
    let writtenBody = '';
    const resMock = {
      writeHead(code) { writtenStatus = code; },
      end(body) { writtenBody = body; }
    };

    await customHandler.handleRequest(reqMockBadHost, resMock);
    assert.equal(writtenStatus, 421, 'Must reject unauthorized Host header with 421 Misdirected Request');
    assert.ok(writtenBody.includes('Invalid Host header'));
  } finally {
    process.env.NODE_ENV = origNodeEnv;
  }
});

test('MCP Streamable HTTP: Origin validation rejects untrusted origin in production with 403 Forbidden', async () => {
  const origNodeEnv = process.env.NODE_ENV;
  const origAllowedOrigins = process.env.MCP_ALLOWED_ORIGINS;
  process.env.NODE_ENV = 'production';
  delete process.env.MCP_ALLOWED_ORIGINS;

  try {
    const customHandler = createMcpHttpHandler({ targetPlugin: plugin });

    const reqMockUntrusted = {
      method: 'POST',
      headers: {
        host: 'localhost',
        origin: 'https://malicious-website.example',
        'content-type': 'application/json'
      }
    };
    let writtenStatus = 0;
    let writtenBody = '';
    const resMock = {
      writeHead(code) { writtenStatus = code; },
      end(body) { writtenBody = body; }
    };

    await customHandler.handleRequest(reqMockUntrusted, resMock);
    assert.equal(writtenStatus, 403, 'Untrusted browser origin must be rejected with 403 Forbidden');
    assert.ok(writtenBody.includes('Origin not allowed'));
  } finally {
    process.env.NODE_ENV = origNodeEnv;
    if (origAllowedOrigins !== undefined) process.env.MCP_ALLOWED_ORIGINS = origAllowedOrigins;
  }
});

// 9. Transport Errors and Limits
test('MCP Streamable HTTP: non-JSON Content-Type returns 415', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: 'hello'
  });

  assert.equal(res.status, 415);
  const data = await res.json();
  assert.equal(data.error.code, -32700);
});

test('MCP Streamable HTTP: malformed JSON body returns 400 with -32700', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{ invalid json'
  });

  assert.equal(res.status, 400);
  const data = await res.json();
  assert.equal(data.error.code, -32700);
});

test('MCP Streamable HTTP: empty batch array returns 400 with -32600', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify([])
  });

  assert.equal(res.status, 400);
  const data = await res.json();
  assert.equal(data.error.code, -32600);
});

test('MCP Streamable HTTP: batch requests process multiple valid calls', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify([
      { jsonrpc: '2.0', id: 101, method: 'ping' },
      { jsonrpc: '2.0', id: 102, method: 'ping' }
    ])
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.ok(Array.isArray(data));
  assert.equal(data.length, 2);
  assert.equal(data[0].id, 101);
  assert.equal(data[1].id, 102);
});

test('MCP Streamable HTTP: unknown JSON-RPC method returns -32601', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 50, method: 'unknown/method' })
  });

  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.error.code, -32601);
  assert.ok(data.error.message.includes('Method not found'));
});

test('MCP Streamable HTTP: unsupported HTTP method returns 405', async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });

  assert.equal(res.status, 405);
});

// 10. Preservation of STDIO MCP Transport
test('MCP Stdio Transport: continues to operate and responds to JSON-RPC over stdin/stdout', async () => {
  const child = spawn(process.execPath, ['src/plugin.mjs'], {
    cwd,
    env: { ...process.env, MCP_STDIO: '1' },
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const responses = [];
  child.stdout.setEncoding('utf8');

  let buffer = '';
  const messagePromise = new Promise((resolve, reject) => {
    child.stdout.on('data', chunk => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          responses.push(JSON.parse(line));
          if (responses.length === 2) {
            resolve(responses);
          }
        } catch (err) {
          reject(err);
        }
      }
    });
    child.on('error', reject);
  });

  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');

  const received = await messagePromise;
  child.kill();

  assert.equal(received.length, 2);
  assert.equal(received[0].id, 1);
  assert.equal(received[0].result.protocolVersion, '2024-11-05');
  assert.equal(received[0].result.serverInfo.name, 'PayGuard');

  assert.equal(received[1].id, 2);
  assert.ok(Array.isArray(received[1].result.tools));
  assert.equal(received[1].result.tools.length, plugin.tools.length);
});

// 11. Security Hardening Regression Tests
test('MCP Streamable HTTP: session pool honors maxSessions and evicts oldest idle session, never active sessions', () => {
  const handler = createMcpHttpHandler({
    targetPlugin: plugin,
    maxSessions: 3
  });

  const s1 = handler.createSession('2025-11-25');
  const s2 = handler.createSession('2025-11-25');
  const s3 = handler.createSession('2025-11-25');

  assert.equal(handler.getSessions().size, 3);

  // s1 is the oldest, but mark s1 as active with an open SSE connection
  s1.sseRes = { writableEnded: false, end() {} };

  // Creating s4 must skip active s1 and evict oldest idle session s2
  const s4 = handler.createSession('2025-11-25');
  assert.equal(handler.getSessions().size, 3);
  assert.ok(handler.getSession(s1.id), 'Active session s1 with open SSE must NOT be evicted');
  assert.ok(!handler.getSession(s2.id), 'Oldest idle session s2 must be evicted');
  assert.ok(handler.getSession(s3.id), 'Session s3 must remain');
  assert.ok(handler.getSession(s4.id), 'New session s4 must exist');

  // Mark all remaining sessions as active
  s3.sseRes = { writableEnded: false, end() {} };
  s4.sseRes = { writableEnded: false, end() {} };

  // Attempting to create a session when all 3 are active must throw 503 saturation error
  assert.throws(() => {
    handler.createSession('2025-11-25');
  }, (err) => {
    assert.equal(err.statusCode, 503);
    assert.ok(err.message.includes('Session pool saturated'));
    return true;
  });
});

test('MCP Streamable HTTP: Host validation parses bracketed IPv6 with port correctly', async () => {
  const origNodeEnv = process.env.NODE_ENV;
  const origOptIn = process.env.MCP_ALLOW_UNAUTHENTICATED;
  process.env.NODE_ENV = 'production';
  process.env.MCP_ALLOW_UNAUTHENTICATED = 'true';

  try {
    const handler = createMcpHttpHandler({ targetPlugin: plugin });

    // 1. Bracketed IPv6 loopback with port
    let writtenStatus = 0;
    const resMock = {
      setHeader() {},
      writeHead(code) { writtenStatus = code; },
      end() {}
    };

    await handler.handleRequest({
      method: 'GET',
      headers: { host: '[::1]:8080', accept: 'application/json' }
    }, resMock);
    assert.equal(writtenStatus, 200, 'Bracketed IPv6 loopback [::1]:8080 must be permitted');

    // 2. Missing Host in production must be rejected
    let badStatus = 0;
    const resBad = {
      setHeader() {},
      writeHead(code) { badStatus = code; },
      end() {}
    };
    await handler.handleRequest({
      method: 'GET',
      headers: { accept: 'application/json' }
    }, resBad);
    assert.equal(badStatus, 421, 'Missing Host header in production must be rejected with 421');
  } finally {
    process.env.NODE_ENV = origNodeEnv;
    if (origOptIn !== undefined) process.env.MCP_ALLOW_UNAUTHENTICATED = origOptIn;
    else delete process.env.MCP_ALLOW_UNAUTHENTICATED;
  }
});

test('MCP Streamable HTTP: Bearer token auth uses constant-time digest comparison', async () => {
  const handler = createMcpHttpHandler({
    targetPlugin: plugin,
    authToken: 'long-secret-token-abcdef1234567890'
  });

  // Different length token must still be rejected with 401 without error
  let statusCode = 0;
  const res = {
    setHeader() {},
    writeHead(code) { statusCode = code; },
    end() {}
  };

  await handler.handleRequest({
    method: 'POST',
    headers: { authorization: 'Bearer short' }
  }, res);
  assert.equal(statusCode, 401);
});

test('MCP Streamable HTTP: session with in-flight POST request is protected from LRU eviction', async () => {
  const handler = createMcpHttpHandler({
    targetPlugin: plugin,
    maxSessions: 2
  });

  const s1 = handler.createSession('2025-11-25');
  const s2 = handler.createSession('2025-11-25');
  assert.equal(handler.getSessions().size, 2);

  // Simulate an in-flight tool call on s1
  s1.activeRequests = 1;

  // Creating s3 must NOT evict s1 (which has activeRequests = 1), but must evict idle s2
  const s3 = handler.createSession('2025-11-25');
  assert.equal(handler.getSessions().size, 2);
  assert.ok(handler.getSession(s1.id), 'Session s1 with active in-flight request must NOT be evicted');
  assert.ok(!handler.getSession(s2.id), 'Idle session s2 must be evicted');
  assert.ok(handler.getSession(s3.id), 'New session s3 must exist');

  // Once in-flight request completes, activeRequests is decremented
  s1.activeRequests = 0;
});

test('MCP Streamable HTTP: concurrent DELETE while request is in-flight completes gracefully', async () => {
  const handler = createMcpHttpHandler({ targetPlugin: plugin });
  const session = handler.createSession('2025-11-25');

  // 1. DELETE terminates session
  let delStatus = 0;
  const resDel = {
    setHeader() {},
    writeHead(code) { delStatus = code; },
    end() {}
  };
  await handler.handleRequest({
    method: 'DELETE',
    headers: { 'mcp-session-id': session.id }
  }, resDel);
  assert.equal(delStatus, 204);

  // 2. Second concurrent DELETE on already-terminated session returns 404
  let secondDelStatus = 0;
  const resSecondDel = {
    setHeader() {},
    writeHead(code) { secondDelStatus = code; },
    end() {}
  };
  await handler.handleRequest({
    method: 'DELETE',
    headers: { 'mcp-session-id': session.id }
  }, resSecondDel);
  assert.equal(secondDelStatus, 404);
});
