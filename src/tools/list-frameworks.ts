/**
 * list_frameworks — extracted from src/index.ts by
 * scripts/apply-sector-regulator-golden-standard.py.
 *
 * Original tool name: no_cyber_list_frameworks
 */

import { listFrameworks } from "../db.js";
import { textContent, errorContent } from "./_helpers.js";



export const LIST_FRAMEWORKS_TOOL = {
  name: "list_frameworks",
  description: "List all NSM frameworks and standard series covered in this MCP, including Grunnprinsipper for IKT-sikkerhet, NIS2 implementation guidance, and nasjonal strategi for digital sikkerhet.",
  inputSchema: {
        type: "object" as const,
        properties: {},
        required: [],
      },
};

export async function handleListFrameworks(args: unknown) {
  const frameworks = listFrameworks();
  return textContent({ frameworks, count: frameworks.length });
}
