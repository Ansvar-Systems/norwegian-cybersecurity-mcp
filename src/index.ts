#!/usr/bin/env node

/**
 * NSM Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying NSM (Nasjonal sikkerhetsmyndighet)
 * guidelines, NorCERT advisories, Grunnprinsipper for IKT-sikkerhet,
 * and digital security frameworks.
 *
 * Tool prefix: no_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "norwegian-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "no_cyber_search_guidance",
    description:
      "Search NSM cybersecurity guidance, advisories, Grunnprinsipper for IKT-sikkerhet, and NorCERT threat assessments. Returns matching documents with reference, title, series, and summary.",
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
  },
  {
    name: "no_cyber_get_guidance",
    description:
      "Get a specific NSM guidance document by ID.",
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
  },
  {
    name: "no_cyber_search_advisories",
    description:
      "Search NorCERT security advisories and vulnerability alerts. Returns advisories with severity, affected products, and CVE references where available.",
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
  },
  {
    name: "no_cyber_get_advisory",
    description:
      "Get a specific NorCERT security advisory by reference.",
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
  },
  {
    name: "no_cyber_list_frameworks",
    description:
      "List all NSM frameworks and standard series covered in this MCP, including Grunnprinsipper for IKT-sikkerhet, NIS2 implementation guidance, and nasjonal strategi for digital sikkerhet.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "no_cyber_about",
    description: "Norwegian Cybersecurity MCP server. Covers NSM Grunnprinsipper for IKT-sikkerhet, NorCERT advisories, and digital security guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guidance", "grunnprinsipp", "standard", "recommendation"]).optional(),
  series: z.enum(["NSM", "NIS2-NO", "Grunnprinsipper"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "no_cyber_search_guidance": {
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

      case "no_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const d = doc as unknown as Record<string, unknown>;
        return textContent({
          ...d,
          _citation: buildCitation({
  canonicalRef: String(d.reference ?? parsed.reference),
  displayText: String(d.title ?? d.reference ?? parsed.reference),
  toolName: "no_cyber_get_guidance",
  toolArgs: { reference: parsed.reference },
  attribution: { source_url: String(d.source_url ?? ""), publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
}),
        });
      }

      case "no_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "no_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const a = advisory as unknown as Record<string, unknown>;
        return textContent({
          ...a,
          _citation: buildCitation({
  canonicalRef: String(a.reference ?? parsed.reference),
  displayText: String(a.title ?? a.reference ?? parsed.reference),
  toolName: "no_cyber_get_advisory",
  toolArgs: { reference: parsed.reference },
  attribution: { source_url: String(a.source_url ?? ""), publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
}),
        });
      }

      case "no_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "no_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "Norwegian Cybersecurity MCP server. Covers NSM Grunnprinsipper for IKT-sikkerhet, NorCERT advisories, and digital security guidance.",
          data_source: "NSM / NorCERT (https://nsm.no/)",
          coverage: {
            guidance: "NSM Grunnprinsipper for IKT-sikkerhet, digital security recommendations, sikkerhetsloven guidance",
            advisories: "NorCERT security advisories and vulnerability alerts",
            frameworks: "Grunnprinsipper for IKT-sikkerhet, NIS2 Norway implementation, nasjonal strategi for digital sikkerhet",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
