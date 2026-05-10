/**
 * search_guidance — extracted from src/index.ts by
 * scripts/apply-sector-regulator-golden-standard.py.
 *
 * Original tool name: no_cyber_search_guidance
 */

import { z } from "zod";
import { searchGuidance } from "../db.js";
import { textContent, errorContent } from "./_helpers.js";

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guidance", "grunnprinsipp", "standard", "recommendation"]).optional(),
  series: z.enum(["NSM", "NIS2-NO", "Grunnprinsipper"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

export const SEARCH_GUIDANCE_TOOL = {
  name: "search_guidance",
  description: "Search NSM cybersecurity guidance, advisories, Grunnprinsipper for IKT-sikkerhet, and NorCERT threat assessments. Returns matching documents with reference, title, series, and summary.",
  inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "Search query (e.g., 'grunnprinsipper', 'IKT-sikkerhet', 'NIS2', 'digital sikkerhet', 'trusselrapport')",
          },
          type: {
            type: "string",
            enum: ["guidance", "grunnprinsipp", "standard", "recommendation"],
            description: "Filter by document type. Optional.",
          },
          series: {
            type: "string",
            enum: ["NSM", "NIS2-NO", "Grunnprinsipper"],
            description: "Filter by NSM series. Optional.",
          },
          status: {
            type: "string",
            enum: ["current", "superseded", "draft"],
            description: "Filter by document status. Defaults to returning all statuses.",
          },
          limit: {
            type: "number",
            description: "Maximum number of results to return. Defaults to 20.",
          },
        },
        required: ["query"],
      },
};

export async function handleSearchGuidance(args: unknown) {
  const parsed = SearchGuidanceArgs.parse(args);
  const results = searchGuidance({
    query: parsed.query,
    type: parsed.type,
    series: parsed.series,
    status: parsed.status,
    limit: parsed.limit,
  });
  return textContent({ results, count: results.length });
}
