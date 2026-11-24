/**
 * @module mcp/streamable-http
 * @section Remote MCP Streamable HTTP Transport Adapter
 *
 * Implements the Model Context Protocol (MCP) Streamable HTTP transport
 * conforming strictly to the 2025 specification revisions:
 * - 2025-03-26: Initial Streamable HTTP transport definition (single endpoint, Mcp-Session-Id).
 * - 2025-06-18: Refined session lifecycle, DELETE handling, and SSE streaming semantics.
 * - 2025-11-25: Canonical Streamable HTTP specification with MCP-Protocol-Version header negotiation.
 *
 * NOTE:
 * - 2024-11-05 is excluded from Streamable HTTP as it represents the legacy dual-endpoint HTTP+SSE spec.
 * - 2026-07-28 is excluded because its stateless architecture (server/discover, metadata envelope)
 *   is not implemented here.
 *
 * Security Policies:
 * - Gated access control in production (requires MCP_AUTH_TOKEN unless MCP_ALLOW_UNAUTHENTICATED=true).
 * - Origin validation against untrusted web origins to mitigate cross-site attacks.
 * - Host header validation against allowed hostnames to prevent DNS rebinding.
 * - Enforced payload size limit (64 KiB) and cryptographically isolated sessions.
 * - Read-only, zero-custody, non-signing security guarantees.
 */

import { randomUUID, timingSafeEqual, createHash } from "node:crypto";
import plugin from "../plugin.mjs";

export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([
  "2025-03-26",
  "2025-06-18",
  "2025-11-25"
]);

export const DEFAULT_PROTOCOL_VERSION = "2025-11-25";
export const LATEST_PROTOCOL_VERSION = "2025-11-25";

const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const DEFAULT_MAX_SESSIONS = 1000;

const DEFAULT_PRODUCTION_ORIGINS = new Set([
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://claude.ai"
]);

/**
 * Resolve allowed CORS origins.
 */
function resolveOriginPolicy(origin, allowedOriginsOption) {
  if (!origin) return null;

  if (allowedOriginsOption) {
    if (allowedOriginsOption === "*" || (Array.isArray(allowedOriginsOption) && allowedOriginsOption.includes("*"))) {
      return "*";
    }
    const list = Array.isArray(allowedOriginsOption)
      ? allowedOriginsOption
      : String(allowedOriginsOption).split(",").map(s => s.trim());
    return list.includes(origin) ? origin : null;
  }

  const envOrigins = process.env.MCP_ALLOWED_ORIGINS;
  if (envOrigins) {
    if (envOrigins.trim() === "*") return "*";
    const list = envOrigins.split(",").map(s => s.trim());
    return list.includes(origin) ? origin : null;
  }

  if (process.env.NODE_ENV !== "production") {
    return origin;
  }

  return DEFAULT_PRODUCTION_ORIGINS.has(origin) ? origin : null;
}

/**
 * Validate Host header to protect against DNS rebinding.
 */
function validateHostHeader(hostHeader, allowedHostsOption) {
  if (!hostHeader) {
    return process.env.NODE_ENV !== "production";
  }
  let host = hostHeader.trim().toLowerCase();
  if (host.startsWith("[")) {
    const closeBracket = host.indexOf("]");
    if (closeBracket !== -1) {
      host = host.slice(0, closeBracket + 1);
    }
  } else {
    host = host.split(":")[0];
  }

  if (allowedHostsOption) {
    const list = Array.isArray(allowedHostsOption)
      ? allowedHostsOption
      : String(allowedHostsOption).split(",").map(s => s.trim().toLowerCase());
    return list.includes(host) || list.includes("*");
  }

  const envHosts = process.env.MCP_ALLOWED_HOSTS;
  if (envHosts) {
    if (envHosts.trim() === "*") return true;
    const list = envHosts.split(",").map(s => s.trim().toLowerCase());
    return list.includes(host);
  }

  // Always permit loopback / local addresses
  if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") {
    return true;
  }

  if (process.env.HOST && host === process.env.HOST.toLowerCase()) {
    return true;
  }

  if (process.env.NODE_ENV !== "production") {
    return true;
  }

  return false;
}

/**
 * Verify authentication token if configured, or enforce production access restrictions.
 */
function verifyAuthentication(req, configuredAuthToken) {
  const token = configuredAuthToken || process.env.MCP_AUTH_TOKEN || process.env.MCP_API_KEY;

  if (token) {
    const authHeader = req.headers["authorization"] || "";
    if (!authHeader.startsWith("Bearer ")) {
      return { authorized: false, status: 401, error: "Unauthorized: Missing Bearer token in Authorization header." };
    }
    const providedToken = authHeader.slice(7).trim();
    const tokenHash = createHash("sha256").update(token).digest();
    const provHash = createHash("sha256").update(providedToken).digest();
    if (!timingSafeEqual(tokenHash, provHash)) {
      return { authorized: false, status: 401, error: "Unauthorized: Invalid Authorization token." };
    }
    return { authorized: true };
  }

  // If no auth token configured:
  // In production, require explicit opt-in via MCP_ALLOW_UNAUTHENTICATED=true
  if (process.env.NODE_ENV === "production" && process.env.MCP_ALLOW_UNAUTHENTICATED !== "true") {
    return {
      authorized: false,
      status: 403,
      error: "Forbidden: Remote MCP endpoint requires authentication in production. Configure MCP_AUTH_TOKEN or set MCP_ALLOW_UNAUTHENTICATED=true."
    };
  }

  return { authorized: true };
}

/**
 * Apply secure CORS headers.
 */
function applyCorsHeaders(res, origin, allowedOriginsOption) {
  const allowed = resolveOriginPolicy(origin, allowedOriginsOption);
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", allowed);
    if (allowed !== "*") {
      res.setHeader("Vary", "Origin");
    }
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version, Accept");
  res.setHeader("Access-Control-Expose-Headers", "Content-Type, Mcp-Session-Id, MCP-Protocol-Version");
  res.setHeader("Access-Control-Max-Age", "86400");
  return Boolean(allowed);
}

/**
 * Negotiate protocol version based on request header or params.
 */
function negotiateProtocolVersion(requestedVersion) {
  if (!requestedVersion) {
    return { version: DEFAULT_PROTOCOL_VERSION, valid: true };
  }
  if (SUPPORTED_PROTOCOL_VERSIONS.includes(requestedVersion)) {
    return { version: requestedVersion, valid: true };
  }
  return { version: requestedVersion, valid: false };
}

/**
 * Create a Streamable HTTP MCP Request Handler.
 */
export function createMcpHttpHandler({
  targetPlugin = plugin,
  authToken = null,
  allowedOrigins = null,
  allowedHosts = null,
  sessionTimeoutMs = DEFAULT_SESSION_TIMEOUT_MS,
  maxSessions = DEFAULT_MAX_SESSIONS,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES
} = {}) {
  if (!targetPlugin || typeof targetPlugin.invokeTool !== "function" || !Array.isArray(targetPlugin.tools)) {
    throw new TypeError("targetPlugin must expose invokeTool(name, input) and a tools array.");
  }

  const sessions = new Map();

  function cleanupExpiredSessions() {
    const now = Date.now();
    for (const [id, session] of sessions.entries()) {
      if (now - session.lastActiveAt > sessionTimeoutMs) {
        if (session.sseRes && !session.sseRes.writableEnded) {
          try {
            session.sseRes.end();
          } catch {}
        }
        sessions.delete(id);
      }
    }
  }

  function getSession(sessionId) {
    if (!sessionId) return null;
    cleanupExpiredSessions();
    const session = sessions.get(sessionId);
    if (session) {
      session.lastActiveAt = Date.now();
      sessions.delete(sessionId);
      sessions.set(sessionId, session);
      return session;
    }
    return null;
  }

  function createSession(negotiatedVersion = DEFAULT_PROTOCOL_VERSION) {
    cleanupExpiredSessions();
    if (sessions.size >= maxSessions) {
      // Find the oldest idle session (no active SSE connection and no active in-flight requests)
      let candidateId = null;
      for (const [id, s] of sessions.entries()) {
        const hasActiveSse = s.sseRes && !s.sseRes.writableEnded;
        const hasActiveRequests = (s.activeRequests || 0) > 0;
        if (!hasActiveSse && !hasActiveRequests) {
          candidateId = id;
          break;
        }
      }
      if (candidateId) {
        terminateSession(candidateId);
      } else {
        const err = new Error("Session pool saturated: maximum active sessions reached.");
        err.statusCode = 503;
        throw err;
      }
    }
    const id = randomUUID();
    const session = {
      id,
      protocolVersion: negotiatedVersion,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      activeRequests: 0,
      sseRes: null
    };
    sessions.set(id, session);
    return session;
  }

  function terminateSession(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
      if (session.sseRes && !session.sseRes.writableEnded) {
        try {
          session.sseRes.end();
        } catch {}
      }
      sessions.delete(sessionId);
      return true;
    }
    return false;
  }

  async function readRequestBody(req) {
    const contentLength = Number(req.headers["content-length"] || 0);
    if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) {
      const err = new Error("Request body exceeds limit.");
      err.statusCode = 413;
      throw err;
    }

    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > maxBodyBytes) {
        const err = new Error("Request body exceeds limit.");
        err.statusCode = 413;
        throw err;
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  async function processJsonRpcMessage(message, session, effectiveVersion) {
    if (!message || typeof message !== "object") {
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid Request: expected JSON object." }
      };
    }

    const { id, method, params } = message;
    const isNotification = id === undefined || id === null;

    if (method === "notifications/initialized") {
      return null;
    }

    if (method === "initialize") {
      const requestedVersion = params?.protocolVersion || effectiveVersion;
      const { version, valid } = negotiateProtocolVersion(requestedVersion);

      if (!valid) {
        return {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32022,
            message: `Unsupported protocol version: ${requestedVersion}. Supported versions: ${SUPPORTED_PROTOCOL_VERSIONS.join(", ")}`,
            data: {
              supportedVersions: SUPPORTED_PROTOCOL_VERSIONS
            }
          }
        };
      }

      // Check consistency between header and initialize param
      if (effectiveVersion && requestedVersion && effectiveVersion !== requestedVersion && params?.protocolVersion) {
        return {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32022,
            message: `Protocol version mismatch: header specified ${effectiveVersion} but initialize params specified ${requestedVersion}.`,
            data: { supportedVersions: SUPPORTED_PROTOCOL_VERSIONS }
          }
        };
      }

      if (session) {
        session.protocolVersion = version;
      }

      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: version,
          capabilities: {
            tools: {
              listChanged: false
            }
          },
          serverInfo: {
            name: targetPlugin.name || "PayGuard",
            version: targetPlugin.version || "0.1.0"
          }
        }
      };
    }

    if (method === "ping") {
      return { jsonrpc: "2.0", id, result: {} };
    }

    if (method === "tools/list") {
      const toolSummaries = targetPlugin.tools.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema
      }));
      return {
        jsonrpc: "2.0",
        id,
        result: {
          tools: toolSummaries
        }
      };
    }

    if (method === "tools/call") {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      if (!toolName || typeof toolName !== "string") {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "Invalid params: 'name' is required and must be a string." }
        };
      }

      try {
        const toolRes = await targetPlugin.invokeTool(toolName, toolArgs);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: typeof toolRes === "string" ? toolRes : JSON.stringify(toolRes, null, 2)
              }
            ],
            isError: false
          }
        };
      } catch (err) {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: `Error executing ${toolName}: ${err?.message || String(err)}`
              }
            ],
            isError: true
          }
        };
      }
    }

    if (isNotification) {
      return null;
    }

    return {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32601,
        message: `Method not found: ${method}`
      }
    };
  }

  async function handleRequest(req, res) {
    // 1. Host header validation for DNS rebinding protection
    const hostHeader = req.headers["host"];
    if (!validateHostHeader(hostHeader, allowedHosts)) {
      res.writeHead(421, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Misdirected Request: Invalid Host header." }));
    }

    // 2. Origin validation & CORS preflight
    const origin = req.headers["origin"] || null;
    if (origin && process.env.NODE_ENV === "production") {
      const allowed = resolveOriginPolicy(origin, allowedOrigins);
      if (!allowed) {
        res.writeHead(403, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Forbidden: Origin not allowed." }));
      }
    }
    applyCorsHeaders(res, origin, allowedOrigins);

    // 3. CORS Preflight (OPTIONS does not require authentication)
    if (req.method === "OPTIONS") {
      res.writeHead(204, { "Content-Length": "0" });
      return res.end();
    }

    // 4. Access Control & Authentication Verification
    const authResult = verifyAuthentication(req, authToken);
    if (!authResult.authorized) {
      const headers = {
        "Content-Type": "application/json",
        ...(authResult.status === 401 ? { "WWW-Authenticate": 'Bearer realm="PayGuard MCP"' } : {})
      };
      res.writeHead(authResult.status, headers);
      return res.end(JSON.stringify({ error: authResult.error }));
    }

    // 5. Extract headers: Session ID & Protocol Version
    const reqSessionId = req.headers["mcp-session-id"] || null;
    const reqProtocolHeader = req.headers["mcp-protocol-version"] || null;

    // Validate protocol version header if provided
    let effectiveVersion = DEFAULT_PROTOCOL_VERSION;
    if (reqProtocolHeader) {
      const { version, valid } = negotiateProtocolVersion(reqProtocolHeader);
      if (!valid) {
        res.writeHead(400, {
          "Content-Type": "application/json",
          "MCP-Protocol-Version": DEFAULT_PROTOCOL_VERSION
        });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32022,
            message: `Unsupported protocol version in MCP-Protocol-Version header: ${reqProtocolHeader}. Supported versions: ${SUPPORTED_PROTOCOL_VERSIONS.join(", ")}`,
            data: { supportedVersions: SUPPORTED_PROTOCOL_VERSIONS }
          }
        }));
      }
      effectiveVersion = version;
    }

    // Session validation
    let session = null;
    if (reqSessionId) {
      session = getSession(reqSessionId);
      if (!session) {
        res.writeHead(404, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32001, message: "Session not found or expired." }
        }));
      }

      // Validate wire behavior: protocol version in session must match header if header was supplied
      if (reqProtocolHeader && session.protocolVersion && reqProtocolHeader !== session.protocolVersion) {
        res.writeHead(400, {
          "Content-Type": "application/json",
          "MCP-Protocol-Version": session.protocolVersion
        });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32022,
            message: `Protocol version mismatch for active session: established version is ${session.protocolVersion}, but request specified ${reqProtocolHeader}.`
          }
        }));
      }
      effectiveVersion = session.protocolVersion || effectiveVersion;
    }

    if (session) {
      session.activeRequests = (session.activeRequests || 0) + 1;
    }

    try {
    // 6. DELETE /mcp -> Terminate session
    if (req.method === "DELETE") {
      if (!reqSessionId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Missing Mcp-Session-Id header." }));
      }
      const terminated = terminateSession(reqSessionId);
      if (terminated) {
        res.writeHead(204, {
          "Content-Length": "0",
          "MCP-Protocol-Version": effectiveVersion
        });
        return res.end();
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Session not found or already expired." }));
    }

    // 7. GET /mcp -> Streamable HTTP SSE stream or Server Metadata
    if (req.method === "GET") {
      const accept = req.headers["accept"] || "";
      const wantsSse = accept.includes("text/event-stream");

      if (wantsSse) {
        if (!session) {
          try {
            session = createSession(effectiveVersion);
            session.activeRequests = (session.activeRequests || 0) + 1;
          } catch (err) {
            const code = err.statusCode || 500;
            res.writeHead(code, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ error: err.message || "Failed to create session." }));
          }
        }

        // Disable socket timeouts for persistent SSE connection
        if (typeof req.setTimeout === "function") req.setTimeout(0);
        if (typeof res.setTimeout === "function") res.setTimeout(0);
        if (req.socket && typeof req.socket.setTimeout === "function") req.socket.setTimeout(0);

        if (session.sseRes && session.sseRes !== res && !session.sseRes.writableEnded) {
          try {
            session.sseRes.end();
          } catch {}
        }

        session.sseRes = res;
        res.writeHead(200, {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          "Connection": "keep-alive",
          "X-Content-Type-Options": "nosniff",
          "Mcp-Session-Id": session.id,
          "MCP-Protocol-Version": session.protocolVersion || effectiveVersion
        });

        // In Streamable HTTP (2025 specifications), keep-alive comments are used.
        // There is no legacy "event: endpoint" discovery event.
        res.write(`: keep-alive\n\n`);

        req.on("close", () => {
          if (session.sseRes === res) {
            session.sseRes = null;
          }
        });
        return;
      }

      const metadata = {
        service: "payguard-mcp",
        protocol: "mcp",
        transport: "streamable-http",
        supportedProtocolVersions: SUPPORTED_PROTOCOL_VERSIONS,
        defaultProtocolVersion: DEFAULT_PROTOCOL_VERSION,
        latestProtocolVersion: LATEST_PROTOCOL_VERSION,
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        toolsCount: targetPlugin.tools.length
      };

      const body = JSON.stringify(metadata, null, 2);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
        "Cache-Control": "no-store",
        "MCP-Protocol-Version": effectiveVersion
      });
      return res.end(body);
    }

    // 8. POST /mcp -> JSON-RPC 2.0 messages
    if (req.method === "POST") {
      const contentType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
      if (contentType !== "application/json") {
        res.writeHead(415, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Unsupported Media Type: Content-Type must be application/json." }
        }));
      }

      let rawBody;
      try {
        rawBody = await readRequestBody(req);
      } catch (err) {
        const code = err.statusCode || 400;
        res.writeHead(code, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: err.message || "Failed to read request body." }
        }));
      }

      let parsedBody;
      try {
        parsedBody = JSON.parse(rawBody);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error: invalid JSON body." }
        }));
      }

      // If initialize call, ensure session is created with negotiated protocol version
      const isInitCall = Array.isArray(parsedBody)
        ? parsedBody.some(m => m?.method === "initialize")
        : parsedBody?.method === "initialize";

      if (!session && isInitCall) {
        try {
          session = createSession(effectiveVersion);
          session.activeRequests = (session.activeRequests || 0) + 1;
        } catch (err) {
          const code = err.statusCode || 500;
          res.writeHead(code, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: Array.isArray(parsedBody) ? null : (parsedBody?.id ?? null),
            error: { code: -32000, message: err.message || "Failed to create session." }
          }));
        }
      }

      // Process single message or batch
      let responsePayload;
      if (Array.isArray(parsedBody)) {
        if (parsedBody.length === 0) {
          res.writeHead(400, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32600, message: "Invalid Request: empty batch array." }
          }));
        }
        const results = await Promise.all(parsedBody.map(m => processJsonRpcMessage(m, session, effectiveVersion)));
        responsePayload = results.filter(Boolean);
      } else {
        responsePayload = await processJsonRpcMessage(parsedBody, session, effectiveVersion);
      }

      // Notification only: 202 Accepted without body
      if (responsePayload === null || (Array.isArray(responsePayload) && responsePayload.length === 0)) {
        const extraHeaders = {
          "MCP-Protocol-Version": session?.protocolVersion || effectiveVersion,
          ...(session ? { "Mcp-Session-Id": session.id } : {})
        };
        res.writeHead(202, {
          "Content-Length": "0",
          ...extraHeaders
        });
        return res.end();
      }

      const resBody = JSON.stringify(responsePayload);
      const accept = req.headers["accept"] || "";
      const wantsSse = accept.includes("text/event-stream");

      const responseHeaders = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "MCP-Protocol-Version": session?.protocolVersion || effectiveVersion,
        ...(session ? { "Mcp-Session-Id": session.id } : {})
      };

      if (wantsSse) {
        const sseFormatted = `event: message\ndata: ${resBody}\n\n`;
        res.writeHead(200, {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Content-Length": Buffer.byteLength(sseFormatted),
          ...responseHeaders
        });
        return res.end(sseFormatted);
      }

      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(resBody),
        ...responseHeaders
      });
      return res.end(resBody);
    }

    res.writeHead(405, {
      "Content-Type": "application/json",
      "Allow": "GET, POST, DELETE, OPTIONS"
    });
    return res.end(JSON.stringify({ error: "Method not allowed." }));
    } finally {
      if (session) {
        session.activeRequests = Math.max(0, (session.activeRequests || 0) - 1);
      }
    }
  }

  return {
    handleRequest,
    getSessions: () => sessions,
    clearSessions: () => sessions.clear(),
    createSession,
    getSession,
    terminateSession,
    SUPPORTED_PROTOCOL_VERSIONS,
    DEFAULT_PROTOCOL_VERSION,
    LATEST_PROTOCOL_VERSION
  };
}

// Global default handler instance
const defaultHandler = createMcpHttpHandler({ targetPlugin: plugin });

export async function handleMcpHttpRequest(req, res, options = {}) {
  if (options.targetPlugin || options.authToken !== undefined || options.allowedOrigins !== undefined || options.allowedHosts !== undefined) {
    const customHandler = createMcpHttpHandler(options);
    return customHandler.handleRequest(req, res);
  }
  return defaultHandler.handleRequest(req, res);
}

export default handleMcpHttpRequest;
