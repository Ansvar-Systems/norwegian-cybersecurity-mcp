/**
 * get_advisory — extracted from src/index.ts by
 * scripts/apply-sector-regulator-golden-standard.py.
 *
 * Original tool name: no_cyber_get_advisory
 */

import { z } from "zod";
import { getAdvisory } from "../db.js";
import { buildCitation } from "../citation.js";
import { textContent, errorContent } from "./_helpers.js";

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

export const GET_ADVISORY_TOOL = {
  name: "get_advisory",
  description: "Get a specific NorCERT security advisory by reference.",
  inputSchema: {
        type: "object" as const,
        properties: {
          reference: {
            type: "string",
            description: "NorCERT advisory reference",
          },
        },
        required: ["reference"],
      },
};

export async function handleGetAdvisory(args: unknown) {
  const parsed = GetAdvisoryArgs.parse(args);
  const advisory = getAdvisory(parsed.reference);
  if (!advisory) {
    return errorContent(`Advisory not found: ${parsed.reference}`);
  }
  const a = advisory as unknown as Record<string, unknown>;
  return textContent({
    ...a,
    _citation: buildCitation(
      String(a.reference ?? parsed.reference),
      String(a.title ?? a.reference ?? parsed.reference),
      "no_cyber_get_advisory",
      { reference: parsed.reference },
    ),
  });
}
