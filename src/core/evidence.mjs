/**
 * PayGuard Evidence Core
 *
 * Builds deterministic, validated, read-only assessment summaries from the
 * Phase B evidence records and Phase C orchestration output.
 */

export const FINDING_CATEGORIES = Object.freeze([
  "CALLDATA",
  "APPROVAL",
  "SIMULATION",
  "REPUTATION",
  "GAS_ANOMALY"
]);

export const ASSESSMENT_SEVERITIES = Object.freeze([
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL"
]);

export const RECOMMENDATION_DECISIONS = Object.freeze([
  "ALLOW",
  "WARN",
  "BLOCK",
  "REVOKE_APPROVAL",
  "REDIRECT_SAFE_VAULT"
]);

export const RISK_WEIGHTS = Object.freeze({
  INFO: 0,
  LOW: 15,
  MEDIUM: 40,
  HIGH: 70,
  CRITICAL: 90
});

const MAX_RULE_ID_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_EVIDENCE_REFS = 32;
const MAX_ASSESSMENT_FINDINGS = 9600;
const ASSESSMENT_KEYS = Object.freeze([
  "riskScore",
  "confidence",
  "decision",
  "findings",
  "recommendedActions",
  "overallStatus",
  "evidenceCoverage"
]);
const EVIDENCE_RECORD_STATUSES = Object.freeze([
  "NOT_CHECKED",
  "PENDING",
  "VERIFIED",
  "RISK_DETECTED",
  "UNVERIFIED",
  "ERROR"
]);
const EVIDENCE_COVERAGE_KEYS = Object.freeze([
  "evidenceId",
  "status",
  "required"
]);
const MAX_EVIDENCE_RECORDS = 32;
const FINDING_KEYS = Object.freeze([
  "ruleId",
  "category",
  "severity",
  "description",
  "metadata"
]);
const RECOMMENDATION_KEYS = Object.freeze([
  "decision",
  "action",
  "reason",
  "evidenceRefs",
  "executionMode",
  "requiresUserApproval"
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isRecord(value) &&
    Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key));
}

function isNonEmptyString(value, maxLength = MAX_DESCRIPTION_LENGTH) {
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

function isJsonRecord(value) {
  if (!isRecord(value)) return false;
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string" && serialized.length <= 16_384;
  } catch {
    return false;
  }
}

function normalizeSeverity(value) {
  const severity = typeof value === "string" ? value.toUpperCase() : "";
  return ASSESSMENT_SEVERITIES.includes(severity) ? severity : "MEDIUM";
}

function categoryFor(source, ruleId) {
  const sourceText = String(source || "").toLowerCase();
  const ruleText = String(ruleId || "").toLowerCase();

  if (/gas/.test(sourceText) || /gas/.test(ruleText)) return "GAS_ANOMALY";
  if (/simulation/.test(sourceText) || /simulation/.test(ruleText)) return "SIMULATION";
  if (/approval|allowance|permit/.test(ruleText)) return "APPROVAL";
  if (sourceText.includes("inspect_calldata") || sourceText.includes("correlation")) return "CALLDATA";
  return "REPUTATION";
}

function findingFromRecord(record, item, index) {
  const ruleId = item?.code || item?.id || record.checkId || record.source || `RISK_FINDING_${index + 1}`;
  const description = item?.message || item?.detail || record.reason || "A security check reported a risk signal.";
  const severity = normalizeSeverity(item?.severity || record.rawOutput?.riskLevel);

  return {
    ruleId: String(ruleId).slice(0, MAX_RULE_ID_LENGTH),
    category: categoryFor(record.source, ruleId),
    severity,
    description: String(description).slice(0, MAX_DESCRIPTION_LENGTH),
    metadata: {
      source: String(record.source || "unknown").slice(0, 128),
      checkId: String(record.checkId || record.source || "unknown").slice(0, 128),
      evidenceId: String(record.id || "").slice(0, 256),
      ...(typeof record.rawOutputSha256 === "string"
        ? { rawOutputSha256: record.rawOutputSha256 }
        : {})
    }
  };
}

function collectFindings(records) {
  const findings = [];

  records.forEach(record => {
    if (record?.status !== "RISK_DETECTED") return;

    const evidence = Array.isArray(record.evidence) ? record.evidence : [];
    if (evidence.length === 0) {
      findings.push(findingFromRecord(record, null, findings.length));
      return;
    }

    evidence.forEach(item => {
      findings.push(findingFromRecord(record, item, findings.length));
    });
  });

  return findings;
}

function calculateRiskScore(findings) {
  if (findings.length === 0) return 0;
  const highest = Math.max(...findings.map(finding => RISK_WEIGHTS[finding.severity]));
  return Math.min(100, highest + Math.max(0, findings.length - 1) * 5);
}

function normalizeEvidenceCoverage(records) {
  return records.map(record => ({
    evidenceId: String(record.id),
    status: record.status,
    required: record.required !== false
  }));
}

function deriveOverallStatus(coverage) {
  if (coverage.some(record => record.status === "RISK_DETECTED")) return "RISK_DETECTED";
  const required = coverage.filter(record => record.required);
  if (required.length === 0) return "NOT_CHECKED";

  const precedence = ["ERROR", "UNVERIFIED", "NOT_CHECKED", "PENDING", "VERIFIED"];
  for (const status of precedence) {
    if (required.some(record => record.status === status)) return status;
  }
  return "NOT_CHECKED";
}

function calculateCoverageConfidence(coverage) {
  const required = coverage.filter(record => record.required);
  if (required.length === 0) return 0;
  const completed = required.filter(record =>
    record.status === "VERIFIED" || record.status === "RISK_DETECTED"
  ).length;
  return Number((completed / required.length).toFixed(4));
}

function validateEvidenceCoverage(coverage) {
  if (!Array.isArray(coverage) || coverage.length > MAX_EVIDENCE_RECORDS) return false;
  const ids = new Set();
  return coverage.every(record => {
    if (!hasExactKeys(record, EVIDENCE_COVERAGE_KEYS)) return false;
    if (!isNonEmptyString(record.evidenceId, 256)) return false;
    if (ids.has(record.evidenceId)) return false;
    ids.add(record.evidenceId);
    return EVIDENCE_RECORD_STATUSES.includes(record.status) &&
      typeof record.required === "boolean";
  });
}

function validateInputEvidenceRecords(records) {
  if (!Array.isArray(records) || records.length > MAX_EVIDENCE_RECORDS) {
    throw new TypeError("Evidence records must be an array containing at most 32 records.");
  }
  for (const [index, record] of records.entries()) {
    if (!isRecord(record) ||
        !isNonEmptyString(record.id, 256) ||
        !EVIDENCE_RECORD_STATUSES.includes(record.status) ||
        (record.required !== undefined && typeof record.required !== "boolean")) {
      throw new TypeError(`Evidence record at index ${index} is malformed or has an unsupported status.`);
    }
  }
}

function decide(findings, overallStatus) {
  if (findings.length === 0) {
    return overallStatus === "VERIFIED" ? "ALLOW" : "WARN";
  }

  const approvalRisk = findings.some(finding =>
    finding.category === "APPROVAL" &&
    ["HIGH", "CRITICAL"].includes(finding.severity)
  );
  if (approvalRisk) return "REVOKE_APPROVAL";

  if (findings.some(finding => ["HIGH", "CRITICAL"].includes(finding.severity))) {
    return "BLOCK";
  }

  return "WARN";
}

function recommendationFor(decision, findings) {
  const evidenceRefs = [...new Set(findings
    .map(finding => finding.metadata.evidenceId)
    .filter(Boolean))].slice(0, MAX_EVIDENCE_REFS);

  const copy = {
    WARN: {
      action: "Pause and manually review the flagged evidence before proceeding.",
      reason: "The assessment is inconclusive or contains findings that require human review."
    },
    BLOCK: {
      action: "Do not proceed with this interaction.",
      reason: "The assessment contains a high or critical security finding."
    },
    REVOKE_APPROVAL: {
      action: "Review the affected allowance and revoke it using a trusted wallet interface if appropriate.",
      reason: "The assessment identified a high or critical approval or allowance risk."
    },
    REDIRECT_SAFE_VAULT: {
      action: "Only consider a destination independently verified by the user.",
      reason: "A user-authorized recovery workflow may be appropriate after independently verifying the destination."
    }
  };

  if (decision === "ALLOW") return [];
  const selected = copy[decision];
  return [{
    decision,
    action: selected.action,
    reason: selected.reason,
    evidenceRefs,
    executionMode: "READ_ONLY_RECOMMENDATION",
    requiresUserApproval: true
  }];
}

export function validateEvidenceFinding(finding) {
  return hasExactKeys(finding, FINDING_KEYS) &&
    isNonEmptyString(finding.ruleId, MAX_RULE_ID_LENGTH) &&
    FINDING_CATEGORIES.includes(finding.category) &&
    ASSESSMENT_SEVERITIES.includes(finding.severity) &&
    isNonEmptyString(finding.description, MAX_DESCRIPTION_LENGTH) &&
    isJsonRecord(finding.metadata);
}

export function validateRecommendedAction(action) {
  return hasExactKeys(action, RECOMMENDATION_KEYS) &&
    RECOMMENDATION_DECISIONS.includes(action.decision) &&
    action.decision !== "ALLOW" &&
    isNonEmptyString(action.action) &&
    isNonEmptyString(action.reason) &&
    Array.isArray(action.evidenceRefs) &&
    action.evidenceRefs.length <= MAX_EVIDENCE_REFS &&
    action.evidenceRefs.every(ref => isNonEmptyString(ref, 256)) &&
    action.executionMode === "READ_ONLY_RECOMMENDATION" &&
    action.requiresUserApproval === true;
}

export function validateEvidenceCore(assessment) {
  if (!hasExactKeys(assessment, ASSESSMENT_KEYS)) return false;
  if (!isFiniteInRange(assessment.riskScore, 0, 100)) return false;
  if (!isFiniteInRange(assessment.confidence, 0, 1)) return false;
  if (!RECOMMENDATION_DECISIONS.includes(assessment.decision)) return false;
  if (!EVIDENCE_RECORD_STATUSES.includes(assessment.overallStatus)) return false;
  if (!validateEvidenceCoverage(assessment.evidenceCoverage)) return false;
  if (!Array.isArray(assessment.findings) || assessment.findings.length > MAX_ASSESSMENT_FINDINGS || !assessment.findings.every(validateEvidenceFinding)) return false;
  if (!Array.isArray(assessment.recommendedActions) ||
      !assessment.recommendedActions.every(validateRecommendedAction)) return false;
  if (assessment.recommendedActions.some(action => action.decision !== assessment.decision)) return false;
  const evidenceIds = new Set(assessment.evidenceCoverage.map(record => record.evidenceId));
  if (assessment.findings.some(finding =>
    typeof finding.metadata.evidenceId !== "string" ||
    !evidenceIds.has(finding.metadata.evidenceId)
  )) return false;
  if (assessment.recommendedActions.some(action =>
    new Set(action.evidenceRefs).size !== action.evidenceRefs.length ||
    action.evidenceRefs.some(ref => !evidenceIds.has(ref))
  )) return false;
  if (assessment.riskScore !== calculateRiskScore(assessment.findings)) return false;
  if (assessment.confidence !== calculateCoverageConfidence(assessment.evidenceCoverage)) return false;
  if (assessment.overallStatus !== deriveOverallStatus(assessment.evidenceCoverage)) return false;
  if ((assessment.findings.length > 0) !== (assessment.overallStatus === "RISK_DETECTED")) return false;

  const required = assessment.evidenceCoverage.filter(record => record.required);
  const highRiskApproval = assessment.findings.some(finding =>
    finding.category === "APPROVAL" && ["HIGH", "CRITICAL"].includes(finding.severity)
  );
  const highRiskFinding = assessment.findings.some(finding =>
    ["HIGH", "CRITICAL"].includes(finding.severity)
  );

  if (assessment.decision === "ALLOW") {
    return assessment.findings.length === 0 &&
      assessment.recommendedActions.length === 0 &&
      assessment.riskScore === 0 &&
      required.length > 0 &&
      required.every(record => record.status === "VERIFIED") &&
      assessment.overallStatus === "VERIFIED" &&
      assessment.confidence > 0;
  }

  if (assessment.recommendedActions.length === 0) return false;
  if (assessment.decision !== decide(assessment.findings, assessment.overallStatus)) return false;
  if (assessment.decision === "BLOCK" && (!highRiskFinding || highRiskApproval)) return false;
  if (assessment.decision === "REVOKE_APPROVAL" && !highRiskApproval) return false;
  if (assessment.decision === "WARN" && highRiskFinding) return false;
  if (assessment.decision === "WARN" &&
      assessment.findings.length === 0 &&
      assessment.overallStatus === "VERIFIED") return false;
  return true;
}

function validationError() {
  return new TypeError("Invalid PayGuard Evidence Core assessment.");
}

export const EvidenceCoreSchema = Object.freeze({
  parse(value) {
    if (!validateEvidenceCore(value)) throw validationError();
    return value;
  },
  safeParse(value) {
    return validateEvidenceCore(value)
      ? { success: true, data: value }
      : { success: false, error: validationError() };
  }
});

export function createRecommendedAction({ decision, action, reason, evidenceRefs = [] } = {}) {
  const recommendation = {
    decision,
    action,
    reason,
    evidenceRefs: [...evidenceRefs],
    executionMode: "READ_ONLY_RECOMMENDATION",
    requiresUserApproval: true
  };
  if (!validateRecommendedAction(recommendation)) throw validationError();
  return recommendation;
}

export function buildEvidenceCore(records, overallStatus) {
  validateInputEvidenceRecords(records);

  const evidenceCoverage = normalizeEvidenceCoverage(records);
  const derivedOverallStatus = deriveOverallStatus(evidenceCoverage);
  if (overallStatus !== undefined && overallStatus !== derivedOverallStatus) {
    throw new TypeError("Supplied overall status does not match the evidence records.");
  }

  const findings = collectFindings(records);
  const decision = decide(findings, derivedOverallStatus);
  const assessment = {
    riskScore: calculateRiskScore(findings),
    confidence: calculateCoverageConfidence(evidenceCoverage),
    decision,
    findings,
    recommendedActions: recommendationFor(decision, findings),
    overallStatus: derivedOverallStatus,
    evidenceCoverage
  };

  return EvidenceCoreSchema.parse(assessment);
}


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

function isLegacyNonEmptyString(value, maxLength) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maxLength;
}

function isLegacyFiniteInRange(value, min, max) {
  return typeof value === "number" &&
    Number.isFinite(value) &&
    value >= min &&
    value <= max;
}

function normalizeLegacyFinding(finding, index) {
  if (typeof finding === "string" && isLegacyNonEmptyString(finding, MAX_DESCRIPTION_LENGTH)) {
    return {
      code: `FINDING_${index + 1}`,
      severity: "info",
      message: finding
    };
  }

  if (!isRecord(finding)) {
    throw new TypeError(`findings[${index}] must be a finding object or non-empty string.`);
  }

  const code = finding.code ?? finding.id;
  const message = finding.message ?? finding.detail;
  const rawSeverity = finding.severity ?? (
    finding.status === "FAIL" || finding.status === "fail" ? "high" :
    finding.status === "WARN" || finding.status === "warning" || finding.status === "warn" ? "medium" :
    "info"
  );
  const severity = typeof rawSeverity === "string" ? rawSeverity.toLowerCase() : rawSeverity;
  const rawStatus = finding.status;
  const normalizedStatus = rawStatus === undefined || rawStatus === null
    ? undefined
    : ["PASS", "WARN", "FAIL", "UNKNOWN"].includes(String(rawStatus).toUpperCase())
      ? String(rawStatus).toUpperCase()
      : null;

  if (!isLegacyNonEmptyString(code, 256)) {
    throw new TypeError(`findings[${index}].code/id must be a non-empty string (max 256 characters).`);
  }
  if (!FINDING_SEVERITIES.includes(severity)) {
    throw new TypeError(`findings[${index}].severity must be one of: ${FINDING_SEVERITIES.join(", ")}.`);
  }
  if (!isLegacyNonEmptyString(message, MAX_DESCRIPTION_LENGTH)) {
    throw new TypeError(`findings[${index}].message/detail must be a non-empty string.`);
  }
  if (rawStatus !== undefined && rawStatus !== null && normalizedStatus === null) {
    throw new TypeError(`findings[${index}].status must be PASS, WARN, FAIL, or UNKNOWN.`);
  }

  return {
    code,
    severity,
    message,
    ...(normalizedStatus ? { status: normalizedStatus } : {})
  };
}

function validateLegacyFinding(finding) {
  if (!isRecord(finding)) return false;
  if (!isLegacyNonEmptyString(finding.code, 256)) return false;
  if (!FINDING_SEVERITIES.includes(finding.severity)) return false;
  if (!isLegacyNonEmptyString(finding.message, MAX_DESCRIPTION_LENGTH)) return false;
  return finding.status === undefined || FINDING_STATUSES.includes(finding.status);
}

function validateLegacyTarget(target) {
  return isRecord(target) &&
    EVIDENCE_TARGET_TYPES.includes(target.type) &&
    isLegacyNonEmptyString(target.identifier, MAX_IDENTIFIER_LENGTH);
}

export function createEvidence({
  sourceModule,
  target,
  status = "PENDING",
  findings = [],
  metadata = {}
} = {}) {
  if (!isLegacyNonEmptyString(sourceModule, MAX_SOURCE_MODULE_LENGTH)) {
    throw new TypeError("sourceModule must be a non-empty string (max 128 characters).");
  }
  if (!EVIDENCE_STATUSES.includes(status)) {
    throw new TypeError(`status must be one of: ${EVIDENCE_STATUSES.join(", ")}.`);
  }
  if (!validateLegacyTarget(target)) {
    throw new TypeError(
      `target must contain type (${EVIDENCE_TARGET_TYPES.join(", ")}) and a non-empty identifier.`
    );
  }
  if (!Array.isArray(findings)) throw new TypeError("findings must be an array.");
  if (!isRecord(metadata)) throw new TypeError("metadata must be an object.");

  const riskScore = metadata.riskScore === undefined ? 0 : metadata.riskScore;
  const confidence = metadata.confidence === undefined ? 0 : metadata.confidence;
  if (!isLegacyFiniteInRange(riskScore, 0, 100)) {
    throw new RangeError("metadata.riskScore must be a finite number from 0 to 100.");
  }
  if (!isLegacyFiniteInRange(confidence, 0, 1)) {
    throw new RangeError("metadata.confidence must be a finite number from 0 to 1.");
  }

  return {
    version: EVIDENCE_VERSION,
    timestamp: new Date().toISOString(),
    sourceModule,
    status,
    target: { type: target.type, identifier: target.identifier },
    findings: findings.map(normalizeLegacyFinding),
    metadata: { ...metadata, riskScore, confidence }
  };
}

export function validateEvidence(evidence) {
  if (!isRecord(evidence)) return false;
  if (evidence.version !== EVIDENCE_VERSION) return false;
  if (!isLegacyNonEmptyString(evidence.sourceModule, MAX_SOURCE_MODULE_LENGTH)) return false;
  if (!EVIDENCE_STATUSES.includes(evidence.status)) return false;
  if (typeof evidence.timestamp !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(evidence.timestamp) ||
      !Number.isFinite(Date.parse(evidence.timestamp))) return false;
  if (!validateLegacyTarget(evidence.target)) return false;
  if (!Array.isArray(evidence.findings) || !evidence.findings.every(validateLegacyFinding)) return false;
  if (!isRecord(evidence.metadata)) return false;
  if (!isLegacyFiniteInRange(evidence.metadata.riskScore, 0, 100)) return false;
  if (!isLegacyFiniteInRange(evidence.metadata.confidence, 0, 1)) return false;
  return true;
}
