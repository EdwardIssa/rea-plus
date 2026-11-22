/** Finite allowance for conformance workflows that resend complete Evidence.
 * Admission-policy regressions exercise the production default separately.
 * Conformance workflows address the complete catalog directly, so they
 * select the full surface explicitly; the lazy connect-time default is
 * exercised by the discovery and gate suites separately.
 */
export const INLINE_EVIDENCE_MCP_ENVIRONMENT = Object.freeze({
  REA_MCP_MAX_INPUT_ELEMENTS: "65536",
  REA_MCP_TOOL_SURFACE: "full",
});
