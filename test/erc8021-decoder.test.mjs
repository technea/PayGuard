import test from "node:test";
import assert from "node:assert/strict";
import {
  extractERC8021Suffix,
  ERC8021_MAGIC_MARKER
} from "../src/core/erc8021-decoder.mjs";

test("1. extractERC8021Suffix parses valid single Schema 0 code", () => {
  // payguard -> 8 bytes: 0x7061796775617264
  // length -> 0x08, schema -> 0x00, marker -> 16 bytes
  const suffix = "7061796775617264080080218021802180218021802180218021";
  const calldata = "0x12345678" + suffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, "0x12345678");
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, true);
  assert.deepEqual(result.attribution.builderCodes, ["payguard"]);
  assert.equal(result.attribution.schemaId, 0);
  assert.equal(result.attribution.identityVerified, false);
  assert.equal(result.attribution.rawSuffix, "0x" + suffix);
  assert.equal(result.attribution.error, null);
});

test("2. extractERC8021Suffix parses valid multiple Schema 0 codes", () => {
  // payguard,base-agent -> 19 bytes (0x13): 70617967756172642c626173652d6167656e74
  const codesHex = "70617967756172642c626173652d6167656e74";
  const suffix = codesHex + "130080218021802180218021802180218021";
  const calldata = "0xabcdef01" + suffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, "0xabcdef01");
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, true);
  assert.deepEqual(result.attribution.builderCodes, ["payguard", "base-agent"]);
  assert.equal(result.attribution.schemaId, 0);
  assert.equal(result.attribution.identityVerified, false);
});

test("3. extractERC8021Suffix handles empty calldata with suffix cleanly", () => {
  // calldata consisting ONLY of the suffix
  const suffix = "7061796775617264080080218021802180218021802180218021";
  const calldata = "0x" + suffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, "0x");
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, true);
  assert.deepEqual(result.attribution.builderCodes, ["payguard"]);
});

test("4. extractERC8021Suffix ignores calldata without ERC-8021 marker", () => {
  const normalCalldata = "0xa9059cbb00000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000064";
  const result = extractERC8021Suffix(normalCalldata);

  assert.equal(result.cleanCalldata, normalCalldata);
  assert.equal(result.attribution.detected, false);
  assert.equal(result.attribution.formatValid, false);
  assert.deepEqual(result.attribution.builderCodes, []);
  assert.equal(result.attribution.identityVerified, false);
});

test("5. Invalid marker is NOT stripped", () => {
  // Last byte is 8022 instead of 8021
  const badMarker = "7061796775617264080080218021802180218021802180218022";
  const calldata = "0x12345678" + badMarker;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, calldata); // MUST NOT STRIP
  assert.equal(result.attribution.detected, false);
  assert.equal(result.attribution.formatValid, false);
});

test("6. Unsupported Schema 1 and Schema 2 are NOT stripped", () => {
  // Schema 1 (0x01)
  const schema1Suffix = "7061796775617264080180218021802180218021802180218021";
  const calldata1 = "0x12345678" + schema1Suffix;
  const res1 = extractERC8021Suffix(calldata1);

  assert.equal(res1.cleanCalldata, calldata1); // MUST NOT STRIP
  assert.equal(res1.attribution.detected, true);
  assert.equal(res1.attribution.formatValid, false);
  assert.equal(res1.attribution.schemaId, 1);
  assert.equal(res1.attribution.error, "UNSUPPORTED_SCHEMA_1");

  // Schema 2 (0x02)
  const schema2Suffix = "7061796775617264080280218021802180218021802180218021";
  const calldata2 = "0x12345678" + schema2Suffix;
  const res2 = extractERC8021Suffix(calldata2);

  assert.equal(res2.cleanCalldata, calldata2); // MUST NOT STRIP
  assert.equal(res2.attribution.detected, true);
  assert.equal(res2.attribution.formatValid, false);
  assert.equal(res2.attribution.schemaId, 2);
  assert.equal(res2.attribution.error, "UNSUPPORTED_SCHEMA_2");
});

test("7. Length overflow is NOT stripped", () => {
  // Length claims 50 bytes (0x32), but calldata only has 8 bytes preceding
  const overflowSuffix = "7061796775617264320080218021802180218021802180218021";
  const calldata = "0x" + overflowSuffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, calldata); // MUST NOT STRIP
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, false);
  assert.equal(result.attribution.error, "MALFORMED_LENGTH_OVERFLOW");
});

test("8. Invalid ASCII or control character in code is NOT stripped", () => {
  // Contains byte 0x01 (control char) in code
  const badAsciiSuffix = "0161796775617264080080218021802180218021802180218021";
  const calldata = "0x12345678" + badAsciiSuffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, calldata); // MUST NOT STRIP
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, false);
  assert.equal(result.attribution.error, "INVALID_ASCII_CHARACTER");
});

test("9. Malformed code format (invalid characters) is NOT stripped", () => {
  // Code contains spaces or invalid symbols
  // "pay guard" -> space is 0x20
  const spaceHex = "706179206775617264"; // 9 bytes (0x09)
  const suffix = spaceHex + "090080218021802180218021802180218021";
  const calldata = "0x12345678" + suffix;

  const result = extractERC8021Suffix(calldata);
  assert.equal(result.cleanCalldata, calldata); // MUST NOT STRIP
  assert.equal(result.attribution.detected, true);
  assert.equal(result.attribution.formatValid, false);
  assert.equal(result.attribution.error, "MALFORMED_CODE_FORMAT");
});

