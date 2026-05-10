/**
 * get_guidance — extracted from src/index.ts by
 * scripts/apply-sector-regulator-golden-standard.py.
 *
 * Original tool name: no_cyber_get_guidance
 */

import { z } from "zod";
import { getGuidance } from "../db.js";
import { buildCitation } from "../citation.js";
import { textContent, errorContent } from "./_helpers.js";

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

export const GET_GUIDANCE_TOOL = {
  name: "get_guidance",
  description: "Get a specific NSM guidance document by ID.",
  inputSchema: {
        type: "object" as const,
        properties: {
          reference: {
            type: "string",
            description: "NSM document reference",
          },
        },
        required: ["reference"],
      },
};

export async function handleGetGuidance(args: unknown) {
  const parsed = GetGuidanceArgs.parse(args);
  const doc = getGuidance(parsed.reference);
  if (!doc) {
    return errorContent(`Guidance document not found: ${parsed.reference}`);
  }
  const d = doc as unknown as Record<string, unknown>;
  return textContent({
    ...d,
    _citation: buildCitation(
      String(d.reference ?? parsed.reference),
      String(d.title ?? d.reference ?? parsed.reference),
      "no_cyber_get_guidance",
      { reference: parsed.reference },
    ),
  });
}
