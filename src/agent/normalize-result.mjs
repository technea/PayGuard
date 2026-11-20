/**
 * @module agent/normalize-result
 * @section Tool result normalization
 * Retains a detached raw result and hash while exposing a bounded normalized view.
 */
import { createHash } from "node:crypto";
import { EVIDENCE_SCHEMA_VERSION, MAX_RAW_OUTPUT_CHARS, TOOL_CATALOG } from "./constants.mjs";
import { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";
import { extractUntrustedText } from "./untrusted-data.mjs";
import { normalizeToolStatus } from "./status.mjs";
import { createErrorEvidence } from "./evidence-record.mjs";

function severityFrom(value, fallback = null) {
  const normalized = typeof value === "string" ? value.toUpperCase() : "";
  if (["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(normalized)) return normalized;
  return fallback;
}

function summarizeEvidence(result) {
  const findings = [];
  if (!result || typeof result !== "object") return findings;

  const add = (code, severity, details = {}) => {
    if (typeof code !== "string" || findings.length >= 200) return;
    const item = {
      code: code.slice(0, 120),
      severity: severityFrom(severity, severityFrom(result.riskLevel,
        String(result.status || result.verdict || "").toUpperCase() === "BLOCK" ? "HIGH" : null))
    };
    for (const key of ["message", "detail", "status", "category", "target", "confidence", "score"]) {
      const value = details[key];
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        item[key === "detail" ? "message" : key] = typeof value === "string" ? value.slice(0, 2048) : value;
      }
    }
    if (details.metadata && typeof details.metadata === "object" && !Array.isArray(details.metadata)) {
      const metadata = Object.fromEntries(Object.entries(details.metadata).filter(([, value]) =>
        value !== undefined && (value === null || ["string", "number", "boolean"].includes(typeof value))
      ));
      if (Object.keys(metadata).length > 0) item.metadata = metadata;
    }
    findings.push(item);
  };

  if (Array.isArray(result.findings)) {
    for (const finding of result.findings.slice(0, 100)) {
      add(finding?.code || finding?.id, finding?.severity, finding);
    }
  }
  if (Array.isArray(result.reasonCodes)) {
    for (const code of result.reasonCodes.slice(0, 100)) add(code, result.riskLevel);
  }
  if (Array.isArray(result.checks)) {
    for (const check of result.checks.slice(0, 100)) {
      if (["fail", "failed", "warning", "unknown"].includes(String(check?.status || "").toLowerCase())) {
        add(check?.id || check?.code, check?.severity, check);
      }
    }
  }

  // Wallet scans report token-level risk separately from top-level findings.
  if (Array.isArray(result.tokens)) {
    for (const token of result.tokens.slice(0, 100)) {
      const tokenRisk = String(token?.verdict || token?.securityStatus || "").toUpperCase();
      const riskLevel = severityFrom(token?.riskLevel,
        token?.isImpersonation === true || ["BLOCK", "SUSPICIOUS", "KNOWN_MALICIOUS"].includes(tokenRisk)
          ? "HIGH"
          : ["HIGH RISK", "SUSPICIOUS"].includes(tokenRisk) ? "HIGH" : null);
      const risky = token?.isImpersonation === true ||
        ["BLOCK", "SUSPICIOUS", "KNOWN_MALICIOUS", "RISK_DETECTED", "HIGH RISK"].includes(tokenRisk) ||
        ["HIGH", "CRITICAL"].includes(riskLevel);
      if (risky) {
        add(token?.contractAddress || token?.tokenAddress || token?.address || token?.symbol || "WALLET_TOKEN_RISK",
          riskLevel || "HIGH", {
            message: token?.reason || token?.riskReason || token?.securityStatus || token?.verdict || "Wallet token risk signal.",
            target: token?.contractAddress || token?.tokenAddress || token?.address,
            category: "WALLET_TOKEN",
            metadata: {
              tokenName: token?.tokenName,
              tokenSymbol: token?.tokenSymbol,
              verdict: token?.verdict,
              securityStatus: token?.securityStatus,
              isImpersonation: token?.isImpersonation
            }
          });
      }
    }
  }

  // An explicit source BLOCK is itself a high-risk signal. Preserve a source
  // finding even when a tool provides no itemized findings array.
  const explicitBlock = String(result.status || result.verdict || "").toUpperCase() === "BLOCK";
  if (explicitBlock && findings.length === 0) {
    add("EXPLICIT_SOURCE_BLOCK", severityFrom(result.riskLevel, "HIGH"), {
      message: result.summary || result.reason || "The source tool explicitly returned BLOCK."
    });
  }

  // Some tools expose only aggregate wallet risk counts. Do not drop the signal.
  if (findings.length === 0 && result.summary && typeof result.summary === "object") {
    const high = Number(result.summary.highRiskCount || 0);
    const suspicious = Number(result.summary.suspiciousCount || 0);
    if (high > 0 || suspicious > 0) {
      add("WALLET_AGGREGATE_RISK", high > 0 ? "HIGH" : "MEDIUM", {
        message: "Wallet scan reported " + high + " high-risk and " + suspicious + " suspicious holding(s).",
        category: "WALLET_TOKEN"
      });
    }
  }

  return findings;
}

export function normalizeToolResult(toolName, rawResult, options = {}) {
  if (!Object.hasOwn(TOOL_CATALOG, toolName)) throw new TypeError("Unknown PayGuard tool: " + toolName);

  const completedAt = options.completedAt || new Date().toISOString();
  const base = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    id: options.id || toolName + ":" + completedAt,
    source: toolName,
    checkId: options.checkId || toolName,
    required: options.required !== false,
    startedAt: options.startedAt || null,
    completedAt,
    durationMs: Number.isFinite(options.durationMs) && options.durationMs >= 0 ? options.durationMs : null
  };

  try {
    const canonical = canonicalJson(rawResult);
    const rawOutputSha256 = createHash("sha256").update(canonical, "utf8").digest("hex");
    if (canonical.length > MAX_RAW_OUTPUT_CHARS) {
      return {
        ...createErrorEvidence(toolName, new Error("Output limit exceeded"), {
          ...base,
          errorCode: "RAW_OUTPUT_LIMIT_EXCEEDED"
        }),
        rawOutputSha256,
        rawOutputSizeChars: canonical.length,
        rawOutputOmittedReason: "MAX_RAW_OUTPUT_CHARS_EXCEEDED"
      };
    }

    const detachedRaw = cloneJsonValue(rawResult);
    const normalized = normalizeToolStatus(toolName, rawResult);
    return {
      ...base,
      status: normalized.status,
      reason: normalized.reason,
      rawOutput: detachedRaw,
      rawOutputSha256,
      rawOutputSizeChars: canonical.length,
      evidence: summarizeEvidence(rawResult),
      untrustedData: extractUntrustedText(rawResult)
    };
  } catch (error) {
    return createErrorEvidence(toolName, error, {
      ...base,
      errorCode: "EVIDENCE_SERIALIZATION_FAILED"
    });
  }
}
