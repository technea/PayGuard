/**
 * @module agent/dimensions
 * @section Independent security status dimensions and versioned assessment schema
 * Separates security verdict, contract verification, data availability, and
 * liquidity status so missing data or zero liquidity never distort safety verdicts.
 */

import Ajv from "ajv";

export const SECURITY_ASSESSMENT_SCHEMA_VERSION = "payguard-security-assessment-v1";

export const SECURITY_VERDICTS = Object.freeze(["PASS", "CAUTION", "BLOCK", "UNKNOWN"]);
export const VERIFICATION_STATUSES = Object.freeze(["VERIFIED", "UNVERIFIED", "NOT_CHECKED"]);
export const DATA_STATUSES = Object.freeze(["FRESH", "STALE", "UNAVAILABLE"]);
export const LIQUIDITY_STATUSES = Object.freeze(["HEALTHY", "THIN", "ZERO", "UNKNOWN"]);

export const SECURITY_ASSESSMENT_JSON_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: true,
  required: ["schemaVersion", "assessmentSchemaVersion", "overallStatus", "dimensions", "normalizedFindings"],
  properties: {
    schemaVersion: { type: "string" },
    assessmentSchemaVersion: { const: SECURITY_ASSESSMENT_SCHEMA_VERSION },
    overallStatus: { type: "string" },
    dimensions: {
      type: "object",
      additionalProperties: false,
      required: ["securityVerdict", "verificationStatus", "dataStatus", "liquidityStatus"],
      properties: {
        securityVerdict: { enum: [...SECURITY_VERDICTS] },
        verificationStatus: { enum: [...VERIFICATION_STATUSES] },
        dataStatus: { enum: [...DATA_STATUSES] },
        liquidityStatus: { enum: [...LIQUIDITY_STATUSES] }
      }
    },
    normalizedFindings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "category",
          "severity",
          "status",
          "description",
          "evidence",
          "source",
          "method",
          "timestamp",
          "recommendedAction"
        ],
        properties: {
          id: { type: "string" },
          category: { type: "string" },
          severity: { enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"] },
          status: { enum: ["RISK_DETECTED", "UNVERIFIED", "ERROR", "NOT_CHECKED", "VERIFIED"] },
          description: { type: "string" },
          evidence: {},
          source: { type: "string" },
          method: { type: "string" },
          timestamp: { type: "string" },
          recommendedAction: { type: "string" }
        }
      }
    }
  }
});

const ajv = new Ajv({ allErrors: true });
const validateAssessmentFn = ajv.compile(SECURITY_ASSESSMENT_JSON_SCHEMA);

export function validateSecurityAssessment(report) {
  const valid = validateAssessmentFn(report);
  return {
    valid: Boolean(valid),
    errors: valid ? [] : (validateAssessmentFn.errors || []).map(err => `${err.instancePath || "/"} ${err.message}`)
  };
}

function normalizeSeverity(value, status) {
  const upper = typeof value === "string" ? value.toUpperCase() : "";
  if (upper === "INFO") return "INFORMATIONAL";
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"].includes(upper)) return upper;
  if (status === "RISK_DETECTED") return "HIGH";
  if (status === "UNVERIFIED" || status === "ERROR" || status === "NOT_CHECKED") return "UNKNOWN";
  return "INFORMATIONAL";
}

function recommendedActionFor(status, severity) {
  if (status === "RISK_DETECTED" && (severity === "CRITICAL" || severity === "HIGH")) {
    return "Do not proceed or sign until the flagged high-risk evidence is resolved.";
  }
  if (status === "RISK_DETECTED") {
    return "Review the flagged finding and verify intent before proceeding.";
  }
  if (status === "UNVERIFIED" || status === "ERROR") {
    return "Treat as unknown risk; retry or verify independently before trusting.";
  }
  if (status === "NOT_CHECKED") {
    return "Run the missing check before relying on this assessment.";
  }
  return "No risk flagged by this check; advisory only.";
}

function inferMethod(source) {
  if (source === "payguard_analyze_url" || source === "payguard_prepare_threat_report") return "static-url-heuristics";
  if (source === "payguard_inspect_calldata" || source === "payguard_check_payment_intent") return "deterministic-policy-decoding";
  if (source === "payguard_verify_contract") return "contract-verification-api";
  if (source === "payguard_inspect_tx_hash") return "base-rpc-tx-inspection";
  if (source === "payguard_evidence_correlation") return "cross-module-correlation";
  return "provider-threat-intelligence";
}

/**
 * Normalize evidence records into the unified 10-field finding structure.
 *
 * @param {Array<object>} records
 * @returns {Array<object>}
 */
export function buildNormalizedFindings(records) {
  if (!Array.isArray(records)) return [];
  const normalized = [];

  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const timestamp = record.completedAt || record.startedAt || new Date().toISOString();
    const method = inferMethod(record.source);
    const category = String(record.source || "unknown");

    const items = Array.isArray(record.evidence) && record.evidence.length > 0
      ? record.evidence
      : [{
          code: record.reason || record.status || "CHECK_RESULT",
          severity: record.status === "RISK_DETECTED" ? "HIGH" : "UNKNOWN",
          message: record.reason || `Check ${record.source} reported ${record.status}.`
        }];

    for (let idx = 0; idx < items.length; idx++) {
      const item = items[idx];
      const code = String(item?.code || record.reason || record.status || "FINDING");
      // Liquidity-only signal must not escalate security severity
      const isLiquidityOnly = code === "NO_DEX_LIQUIDITY";
      const itemStatus = isLiquidityOnly && record.status === "RISK_DETECTED"
        ? "UNVERIFIED"
        : (record.status || "UNKNOWN");
      const severity = isLiquidityOnly
        ? "INFORMATIONAL"
        : normalizeSeverity(item?.severity, itemStatus);

      normalized.push({
        id: `${record.id || category}:${code}:${idx}`,
        category,
        severity,
        status: itemStatus,
        description: typeof item?.message === "string" && item.message.trim()
          ? item.message
          : `${category}: ${code}`,
        evidence: item?.metadata ?? { code, rawStatus: record.rawOutput?.verdict || record.rawOutput?.status || null },
        source: String(record.rawOutput?.provider || record.rawOutput?.source || category),
        method,
        timestamp,
        recommendedAction: recommendedActionFor(itemStatus, severity)
      });
    }
  }

  return normalized;
}

/**
 * Derive the four independent security status dimensions from normalized records.
 *
 * @param {Array<object>} records
 * @returns {{ securityVerdict: string, verificationStatus: string, dataStatus: string, liquidityStatus: string }}
 */
export function deriveSecurityDimensions(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return {
      securityVerdict: "UNKNOWN",
      verificationStatus: "NOT_CHECKED",
      dataStatus: "UNAVAILABLE",
      liquidityStatus: "UNKNOWN"
    };
  }

  // 1. Verification Status (from payguard_verify_contract or GoPlus is_open_source)
  let verificationStatus = "NOT_CHECKED";
  const verifyRecord = records.find(r => r?.source === "payguard_verify_contract");
  if (verifyRecord && verifyRecord.status !== "NOT_CHECKED") {
    const rawVerify = verifyRecord.rawOutput?.verificationStatus;
    if (rawVerify === "VERIFIED") verificationStatus = "VERIFIED";
    else if (rawVerify === "UNVERIFIED") verificationStatus = "UNVERIFIED";
  } else {
    const tokenRecord = records.find(r => r?.source === "payguard_check_token_security" && r?.rawOutput?.dataStatus === "AVAILABLE");
    if (tokenRecord) {
      const closed = (tokenRecord.rawOutput?.reasonCodes || []).includes("CLOSED_SOURCE_BYTECODE");
      verificationStatus = closed ? "UNVERIFIED" : "VERIFIED";
    }
  }

  // 2. Data Status
  const activeRecords = records.filter(r => r?.source !== "payguard_verify_contract");
  const hasAnyErrorOrUnavailable = activeRecords.some(r =>
    r?.status === "ERROR" ||
    r?.status === "UNVERIFIED" ||
    r?.status === "NOT_CHECKED" ||
    r?.rawOutput?.dataStatus === "UNAVAILABLE" ||
    r?.rawOutput?.dataStatus === "ERROR" ||
    r?.rawOutput?.dataStatus === "INCOMPLETE"
  );
  const hasAnyFresh = activeRecords.some(r =>
    r?.status === "VERIFIED" ||
    r?.status === "RISK_DETECTED" ||
    r?.rawOutput?.dataStatus === "AVAILABLE" ||
    r?.rawOutput?.dataStatus === "FRESH"
  );
  const hasStale = activeRecords.some(r => r?.rawOutput?.cached === true || r?.rawOutput?.dataStatus === "STALE");
  const dataStatus = !hasAnyFresh && hasAnyErrorOrUnavailable
    ? "UNAVAILABLE"
    : hasAnyErrorOrUnavailable || hasStale
      ? "STALE"
      : "FRESH";

  // 3. Liquidity Status (never overrides securityVerdict)
  let liquidityStatus = "UNKNOWN";
  const tokenRecord = records.find(r => r?.source === "payguard_check_token_security" && r?.rawOutput?.dataStatus === "AVAILABLE");
  if (tokenRecord) {
    const codes = Array.isArray(tokenRecord.rawOutput?.reasonCodes) ? tokenRecord.rawOutput.reasonCodes : [];
    liquidityStatus = codes.includes("NO_DEX_LIQUIDITY") ? "ZERO" : "HEALTHY";
  }

  // 4. Security Verdict (independent of zero liquidity and unverified contract status alone)
  const securityRecords = records.filter(r => r?.source !== "payguard_verify_contract");
  let hasBlock = false;
  let hasCaution = false;
  let hasUnknown = false;
  let hasVerified = false;

  for (const record of securityRecords) {
    if (!record) continue;
    const rawVerdict = String(record.rawOutput?.verdict || record.rawOutput?.status || "").toUpperCase();
    const rawFindings = Array.isArray(record.evidence) ? record.evidence : [];
    const nonLiquidityFindings = rawFindings.filter(f => f?.code !== "NO_DEX_LIQUIDITY" && f?.code !== "CLOSED_SOURCE_BYTECODE");

    if (record.status === "RISK_DETECTED") {
      // Ignore pure zero-liquidity or closed-source-only signals for securityVerdict escalation
      if (nonLiquidityFindings.length === 0 && rawFindings.length > 0) {
        hasUnknown = true;
        continue;
      }
      const hasCriticalOrHigh = nonLiquidityFindings.some(f => ["CRITICAL", "HIGH"].includes(String(f?.severity || "").toUpperCase()));
      if (rawVerdict === "BLOCK" || rawVerdict === "KNOWN_MALICIOUS" || hasCriticalOrHigh) {
        hasBlock = true;
      } else {
        hasCaution = true;
      }
    } else if (record.status === "UNVERIFIED" || record.status === "ERROR" || record.status === "NOT_CHECKED") {
      hasUnknown = true;
    } else if (record.status === "VERIFIED") {
      hasVerified = true;
    }
  }

  const securityVerdict = hasBlock
    ? "BLOCK"
    : hasCaution
      ? "CAUTION"
      : hasUnknown || !hasVerified || dataStatus === "UNAVAILABLE"
        ? "UNKNOWN"
        : "PASS";

  return {
    securityVerdict,
    verificationStatus,
    dataStatus,
    liquidityStatus
  };
}

