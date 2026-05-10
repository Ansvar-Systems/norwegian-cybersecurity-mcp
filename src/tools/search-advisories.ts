/**
 * search_advisories — extracted from src/index.ts by
 * scripts/apply-sector-regulator-golden-standard.py.
 *
 * Original tool name: no_cyber_search_advisories
 */

import { z } from "zod";
import { searchAdvisories } from "../db.js";
import { textContent, errorContent } from "./_helpers.js";

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

export const SEARCH_ADVISORIES_TOOL = {
  name: "search_advisories",
  description: "Search NorCERT security advisories and vulnerability alerts. Returns advisories with severity, affected products, and CVE references where available.",
  inputSchema: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "Search query (e.g., 'kritisk sarbarhet', 'ransomware', 'VPN')",
          },
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low"],
            description: "Filter by severity level. Optional.",
          },
          limit: {
            type: "number",
            description: "Maximum number of results to return. Defaults to 20.",
          },
        },
        required: ["query"],
      },
};

export async function handleSearchAdvisories(args: unknown) {
  const parsed = SearchAdvisoriesArgs.parse(args);
  const results = searchAdvisories({
    query: parsed.query,
    severity: parsed.severity,
    limit: parsed.limit,
  });
  return textContent({ results, count: results.length });
}
