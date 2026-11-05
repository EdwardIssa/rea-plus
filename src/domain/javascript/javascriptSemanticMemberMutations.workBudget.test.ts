import { describe, expect, it } from "vitest";

import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";
import {
  semanticResourceLimitCoverage,
  semanticCoverageResourceLimits,
} from "./javascriptSemanticCoverage.js";
import {
  SEMANTIC_MEMBER_MUTATION_WORK_LIMIT,
  semanticResourceLimitReason,
} from "./javascriptSemanticResourceLimits.js";
import { javaScriptSemanticResourceLimitSchema } from "./javascriptSemanticValueTypes.js";

describe("member-mutation work budget", () => {
  it("classifies the bound as a semantic resource limit end to end", () => {
    expect(
      javaScriptSemanticResourceLimitSchema.parse("member-mutation-work"),
    ).toBe("member-mutation-work");
    expect(semanticResourceLimitReason("member-mutation-work")).toContain(
      String(SEMANTIC_MEMBER_MUTATION_WORK_LIMIT),
    );
    expect(semanticResourceLimitCoverage(["member-mutation-work"])).toEqual([
      {
        name: "javascript_semantic_member_mutation_work",
        value: SEMANTIC_MEMBER_MUTATION_WORK_LIMIT,
        unit: "items",
      },
    ]);
  });

  it("does not bound ordinary member-mutation indexing", () => {
    const ir = analyzeJavaScriptSemantics(`
      const shared = { value: 1 };
      const alias = shared;
      alias.value = 2;
      exports.result = alias.value;
      const copy = { ...shared };
      copy.value = 3;
    `);
    expect(semanticCoverageResourceLimits(ir.coverage)).not.toContain(
      "member-mutation-work",
    );
    expect(ir.coverage.status).toBe("complete");
  });
});
