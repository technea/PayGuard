/**
 * @module agent/planner-validation
 * @section Runtime Planner Output validation
 * Ajv Draft 2020-12 validation. This module validates structure only;
 * tool authorization and dependency-graph checks remain separate runtime gates.
 */
import Ajv2020 from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";

const schemaUrl = new URL("../../schemas/agent/planner-output-v1.0.2.schema.json", import.meta.url);
export const PLANNER_OUTPUT_SCHEMA = JSON.parse(readFileSync(fileURLToPath(schemaUrl), "utf8"));

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: false,
  messages: true
});

const validateSchema = ajv.compile(PLANNER_OUTPUT_SCHEMA);

export class PlannerOutputValidationError extends TypeError {
  constructor(errors) {
    super("Planner output failed Draft 2020-12 schema validation.");
    this.name = "PlannerOutputValidationError";
    this.code = "PLANNER_OUTPUT_SCHEMA_INVALID";
    this.validationErrors = errors;
  }
}

/**
 * Validate a planner response before any tool dispatch.
 * Returns the original value on success; never coerces or mutates planner data.
 */
export function validatePlannerOutput(value) {
  if (!validateSchema(value)) {
    const errors = (validateSchema.errors ?? []).map(error => ({
      instancePath: error.instancePath,
      schemaPath: error.schemaPath,
      keyword: error.keyword,
      message: error.message,
      params: error.params
    }));
    throw new PlannerOutputValidationError(errors);
  }

  const allowedToolErrors = [];
  for (const [index, call] of value.toolCalls.entries()) {
    if (!isKnownPayGuardTool(call.toolName)) {
      allowedToolErrors.push({
        instancePath: `/toolCalls/${index}/toolName`,
        keyword: "toolAllowlist",
        message: "Tool is not registered in the trusted PayGuard tool catalogue."
      });
    }
  }
  if (allowedToolErrors.length) {
    const error = new PlannerOutputValidationError(allowedToolErrors);
    error.code = "PLANNER_OUTPUT_TOOL_NOT_ALLOWED";
    throw error;
  }

  return value;
}

export function getPlannerOutputSchemaErrors(value) {
  validateSchema(value);
  return (validateSchema.errors ?? []).map(error => ({
    instancePath: error.instancePath,
    schemaPath: error.schemaPath,
    keyword: error.keyword,
    message: error.message,
    params: error.params
  }));
}
