/**
 * PayGuard Evidence Core
 *
 * Normalizes the existing URL Sentinel, GoPlus token/address, and calldata
 * inspector outputs without treating their module-specific verdict strings as
 * Evidence Core statuses.
 */

export const EVIDENCE_STATUSES = Object.freeze([
  "NOT_CHECKED",
  "PENDING",
  "VERIFIED",
  "RISK_DETECTED",
  "UNVERIFIED",
  "ERROR"
]);

export const EVIDENCE_TARGET_TYPES = Object.freeze([
  "url",
  "token",
  "address",
  "transaction",
  "payload"
]);

export const FINDING_SEVERITIES = Object.freeze([
  "info",
  "low",
  "medium",
  "high",
  "critical"
]);

export const FINDING_STATUSES = Object.freeze([
  "PASS",
  "WARN",
  "FAIL",
  "UNKNOWN"
]);

const EVIDENCE_VERSION = "1.0.0";
const MAX_SOURCE_MODULE_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 2048;
const MAX_FINDING_TEXT_LENGTH = 4096;

export const EvidenceSchema = Object.freeze({
  version: EVIDENCE_VERSION,
  timestamp: null,
  sourceModule: "",
  status: "PENDING",
  target: {
    type: "",
    identifier: ""
  },
  findings: [],
  metadata: {
    riskScore: 0,
    confidence: 0
  }
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value, maxLength) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maxLength;
}

function isFiniteInRange(value, min, max) {
  return typeof value === "number" &&
    Number.isFinite(value) &&
    value >= min &&
    value <= max;
}

function normalizeFinding(finding, index) {
  if (typeof finding === "string" && isNonEmptyString(finding, MAX_FINDING_TEXT_LENGTH)) {
    return {
      code: `FINDING_${index + 1}`,
      severity: "info",
      message: finding
    };
  }

  if (!isRecord(finding)) {
    throw new TypeError(`findings[${index}] must be a finding object or non-empty string.`);
  }

  // Existing module contracts:
  // GoPlus: { code, severity, message }
  // URL Sentinel: { id, severity, status, detail }
  // Calldata Inspector: { id, status, detail }
  const code = finding.code ?? finding.id;
  const message = finding.message ?? finding.detail;
  const rawSeverity = finding.severity ?? (
    finding.status === "FAIL" || finding.status === "fail" ? "high" :
    finding.status === "WARN" || finding.status === "warning" || finding.status === "warn" ? "medium" :
    "info"
  );
  const severity = typeof rawSeverity === "string" ? rawSeverity.toLowerCase() : rawSeverity;
  const rawStatus = finding.status;
  const status = rawStatus === undefined || rawStatus === null
    ? undefined
    : String(rawStatus).toUpperCase() === "PASS" || String(rawStatus).toLowerCase() === "pass" ? "PASS"
    : String(rawStatus).toUpperCase() === "WARN" || String(rawStatus).toLowerCase() === "warning" || String(rawStatus).toLowerCase() === "warn" ? "WARN"
    : String(rawStatus).toUpperCase() === "FAIL" || String(rawStatus).toLowerCase() === "fail" ? "FAIL"
    : String(rawStatus).toUpperCase() === "UNKNOWN" || String(rawStatus).toLowerCase() === "unknown" ? "UNKNOWN"
    : null;

  if (!isNonEmptyString(code, 256)) {
    throw new TypeError(`findings[${index}].code/id must be a non-empty string (max 256 characters).`);
  }
  if (!FINDING_SEVERITIES.includes(severity)) {
    throw new TypeError(`findings[${index}].severity must be one of: ${FINDING_SEVERITIES.join(", ")}.`);
  }
  if (!isNonEmptyString(message, MAX_FINDING_TEXT_LENGTH)) {
    throw new TypeError(`findings[${index}].message/detail must be a non-empty string.`);
  }
  if (rawStatus !== undefined && rawStatus !== null && status === null) {
    throw new TypeError(`findings[${index}].status must be PASS, WARN, FAIL, or UNKNOWN.`);
  }

  return {
    code,
    severity,
    message,
    ...(status ? { status } : {})
  };
}

function validateTarget(target) {
  return isRecord(target) &&
    EVIDENCE_TARGET_TYPES.includes(target.type) &&
    isNonEmptyString(target.identifier, MAX_IDENTIFIER_LENGTH);
}

function validateFinding(finding) {
  if (!isRecord(finding)) return false;
  if (!isNonEmptyString(finding.code, 256)) return false;
  if (!FINDING_SEVERITIES.includes(finding.severity)) return false;
  if (!isNonEmptyString(finding.message, MAX_FINDING_TEXT_LENGTH)) return false;
  return finding.status === undefined || FINDING_STATUSES.includes(finding.status);
}

/**
 * Create a standardized evidence record.
 *
 * Findings may use the native shapes returned by PayGuard modules:
 * - GoPlus token/address: { code, severity, message }
 * - URL Sentinel: { id, severity, status, detail }
 * - Calldata Inspector: { id, status, detail }
 * A string finding is also accepted and normalized as informational evidence.
 */
export function createEvidence({
  sourceModule,
  target,
  status = "PENDING",
  findings = [],
  metadata = {}
} = {}) {
  if (!isNonEmptyString(sourceModule, MAX_SOURCE_MODULE_LENGTH)) {
    throw new TypeError("sourceModule must be a non-empty string (max 128 characters).");
  }
  if (!EVIDENCE_STATUSES.includes(status)) {
    throw new TypeError(`status must be one of: ${EVIDENCE_STATUSES.join(", ")}.`);
  }
  if (!validateTarget(target)) {
    throw new TypeError(
      `target must contain type (${EVIDENCE_TARGET_TYPES.join(", ")}) and a non-empty identifier.`
    );
  }
  if (!Array.isArray(findings)) {
    throw new TypeError("findings must be an array.");
  }
  if (!isRecord(metadata)) {
    throw new TypeError("metadata must be an object.");
  }

  const riskScore = metadata.riskScore === undefined ? 0 : metadata.riskScore;
  const confidence = metadata.confidence === undefined ? 0 : metadata.confidence;

  if (!isFiniteInRange(riskScore, 0, 100)) {
    throw new RangeError("metadata.riskScore must be a finite number from 0 to 100.");
  }
  if (!isFiniteInRange(confidence, 0, 1)) {
    throw new RangeError("metadata.confidence must be a finite number from 0 to 1.");
  }

  const normalizedFindings = findings.map(normalizeFinding);

  return {
    version: EVIDENCE_VERSION,
    timestamp: new Date().toISOString(),
    sourceModule,
    status,
    target: {
      type: target.type,
      identifier: target.identifier
    },
    findings: normalizedFindings,
    metadata: {
      ...metadata,
      riskScore,
      confidence
    }
  };
}

/**
 * Validate a complete standardized evidence record.
 * Returns false rather than throwing for untrusted input.
 */
export function validateEvidence(evidence) {
  if (!isRecord(evidence)) return false;
  if (evidence.version !== EVIDENCE_VERSION) return false;
  if (!isNonEmptyString(evidence.sourceModule, MAX_SOURCE_MODULE_LENGTH)) return false;
  if (!EVIDENCE_STATUSES.includes(evidence.status)) return false;

  if (typeof evidence.timestamp !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(evidence.timestamp) ||
      !Number.isFinite(Date.parse(evidence.timestamp))) {
    return false;
  }

  if (!validateTarget(evidence.target)) return false;
  if (!Array.isArray(evidence.findings) || !evidence.findings.every(validateFinding)) return false;
  if (!isRecord(evidence.metadata)) return false;
  if (!isFiniteInRange(evidence.metadata.riskScore, 0, 100)) return false;
  if (!isFiniteInRange(evidence.metadata.confidence, 0, 1)) return false;

  return true;
}
