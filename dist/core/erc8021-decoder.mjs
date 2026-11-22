/**
 * PayGuard ERC-8021 Calldata Attribution Decoder
 *
 * Provides pure, deterministic, read-only parsing of ERC-8021 attribution suffixes
 * from proposed EVM transaction calldata.
 *
 * Specification Source:
 * Official Base Builder Codes specification (ERC-8021 via ox/erc8021):
 * - Magic Suffix Marker: 16 bytes = 0x80218021802180218021802180218021
 * - Schema ID: 1 byte immediately preceding the magic marker
 * - Schema 0 (Verified):
 *     [codes ASCII string] + [codesLength (1 byte)] + [schemaId = 0x00 (1 byte)] + [magic marker (16 bytes)]
 *     Total suffix size: 18 + codesLength bytes
 * - Schema 1 & Schema 2:
 *     Treated as UNSUPPORTED per specification until exact parsing semantics are independently verified.
 *
 * Security Invariants:
 * 1. Pure & Read-Only: Never modifies transaction intent, never signs, broadcasts, or executes calldata.
 * 2. Strict Stripping: NEVER strip trailing bytes unless the complete suffix passes strict end-to-end validation.
 * 3. Fail-Closed on Malformed: Ambiguous, truncated, or invalid suffixes are NOT stripped, preserving raw calldata for inspection.
 * 4. Zero Safety Endorsement: `identityVerified` is unconditionally FALSE.
 *    Attribution presence is strictly informational and must NEVER downgrade or bypass risk verdicts.
 */

export const ERC8021_MAGIC_MARKER = "80218021802180218021802180218021"; // 16 bytes (32 hex characters)
export const ERC8021_MAGIC_MARKER_BYTES = 16;
export const ERC8021_MIN_SUFFIX_BYTES = 18; // 1 byte length + 1 byte schemaId + 16 bytes marker

// Whitelist regex for valid Base builder codes (comma-separated ASCII identifiers)
const BUILDER_CODE_REGEX = /^[a-zA-Z0-9_.-]+$/;

/**
 * Parses an ERC-8021 attribution suffix from raw transaction calldata.
 *
 * @param {string} rawCalldata - The 0x-prefixed hex calldata string
 * @returns {Object} Result containing:
 *   - cleanCalldata: string (calldata with valid suffix stripped, or original calldata if no valid suffix)
 *   - attribution: {
 *       detected: boolean,
 *       formatValid: boolean,
 *       builderCodes: string[],
 *       schemaId: number | null,
 *       rawSuffix: string | null,
 *       identityVerified: false,
 *       error: string | null
 *     }
 */
export function extractERC8021Suffix(rawCalldata) {
  const defaultAttribution = {
    detected: false,
    formatValid: false,
    builderCodes: [],
    schemaId: null,
    rawSuffix: null,
    identityVerified: false,
    error: null
  };

  if (typeof rawCalldata !== "string" || !rawCalldata.startsWith("0x")) {
    return {
      cleanCalldata: typeof rawCalldata === "string" ? rawCalldata : "0x",
      attribution: defaultAttribution
    };
  }

  // Hex string without 0x prefix
  const hex = rawCalldata.slice(2).toLowerCase();

  // Must have at least 18 bytes (36 hex characters) for any valid suffix
  if (hex.length < ERC8021_MIN_SUFFIX_BYTES * 2) {
    return {
      cleanCalldata: rawCalldata,
      attribution: defaultAttribution
    };
  }

  // Check if trailing 16 bytes match the ERC-8021 magic marker
  const trailingMarker = hex.slice(-32);
  if (trailingMarker !== ERC8021_MAGIC_MARKER) {
    return {
      cleanCalldata: rawCalldata,
      attribution: defaultAttribution
    };
  }

  // Suffix marker is detected!
  const detected = true;

  // Schema ID is at offset -34 to -32 (1 byte)
  const schemaIdHex = hex.slice(-34, -32);
  const schemaId = parseInt(schemaIdHex, 16);

  // Per specification: Only Schema 0 is fully supported.
  // Schema 1 and 2 are treated as unsupported until their exact encoding/decoding is independently verified.
  if (schemaId !== 0) {
    return {
      cleanCalldata: rawCalldata, // DO NOT STRIP unsupported schemas
      attribution: {
        detected,
        formatValid: false,
        builderCodes: [],
        schemaId,
        rawSuffix: null,
        identityVerified: false,
        error: `UNSUPPORTED_SCHEMA_${schemaId}`
      }
    };
  }

  // Schema 0 Parsing:
  // Length byte is at offset -36 to -34 (1 byte)
  const codesLengthHex = hex.slice(-36, -34);
  const codesLength = parseInt(codesLengthHex, 16);

  const totalSuffixBytes = ERC8021_MIN_SUFFIX_BYTES + codesLength;
  const totalSuffixHexChars = totalSuffixBytes * 2;

  // Ensure calldata is long enough to contain the claimed suffix
  if (hex.length < totalSuffixHexChars) {
    return {
      cleanCalldata: rawCalldata, // DO NOT STRIP on length overflow
      attribution: {
        detected,
        formatValid: false,
        builderCodes: [],
        schemaId: 0,
        rawSuffix: null,
        identityVerified: false,
        error: "MALFORMED_LENGTH_OVERFLOW"
      }
    };
  }

  // Slice the codes payload
  const suffixStart = hex.length - totalSuffixHexChars;
  const codesStart = suffixStart;
  const codesEnd = suffixStart + codesLength * 2;
  const codesHex = hex.slice(codesStart, codesEnd);

  // Decode codes from hex ASCII
  let codesString = "";
  for (let i = 0; i < codesHex.length; i += 2) {
    const codePoint = parseInt(codesHex.slice(i, i + 2), 16);
    // Disallow non-printable or control characters
    if (codePoint < 32 || codePoint > 126) {
      return {
        cleanCalldata: rawCalldata, // DO NOT STRIP on invalid ASCII
        attribution: {
          detected,
          formatValid: false,
          builderCodes: [],
          schemaId: 0,
          rawSuffix: null,
          identityVerified: false,
          error: "INVALID_ASCII_CHARACTER"
        }
      };
    }
    codesString += String.fromCharCode(codePoint);
  }

  // Parse comma-separated builder codes
  const rawCodes = codesString.length > 0 ? codesString.split(",") : [];
  const builderCodes = [];

  for (const code of rawCodes) {
    const trimmed = code.trim();
    if (!trimmed || !BUILDER_CODE_REGEX.test(trimmed)) {
      return {
        cleanCalldata: rawCalldata, // DO NOT STRIP on invalid code format
        attribution: {
          detected,
          formatValid: false,
          builderCodes: [],
          schemaId: 0,
          rawSuffix: null,
          identityVerified: false,
          error: "MALFORMED_CODE_FORMAT"
        }
      };
    }
    builderCodes.push(trimmed);
  }

  // If length > 0 but no valid codes found
  if (codesLength > 0 && builderCodes.length === 0) {
    return {
      cleanCalldata: rawCalldata,
      attribution: {
        detected,
        formatValid: false,
        builderCodes: [],
        schemaId: 0,
        rawSuffix: null,
        identityVerified: false,
        error: "EMPTY_CODES_PAYLOAD"
      }
    };
  }

  // Complete suffix has passed strict validation!
  const rawSuffixHex = "0x" + hex.slice(suffixStart);
  const cleanHex = hex.slice(0, suffixStart);
  const cleanCalldata = cleanHex.length === 0 ? "0x" : "0x" + cleanHex;

  return {
    cleanCalldata,
    attribution: {
      detected: true,
      formatValid: true,
      builderCodes,
      schemaId: 0,
      rawSuffix: rawSuffixHex,
      identityVerified: false, // Invariant: ALWAYS false
      error: null
    }
  };
}

export default {
  ERC8021_MAGIC_MARKER,
  ERC8021_MAGIC_MARKER_BYTES,
  ERC8021_MIN_SUFFIX_BYTES,
  extractERC8021Suffix
};
