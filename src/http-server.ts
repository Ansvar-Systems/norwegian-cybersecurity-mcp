#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_DIR = join(__dirname, "..", "data");

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "norwegian-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Tool definitions (shared with index.ts) ---------------------------------

const TOOLS = [
  {
    name: "no_cyber_search_guidance",
    description:
      "Search NSM cybersecurity guidance, advisories, Grunnprinsipper for IKT-sikkerhet, and NorCERT threat assessments.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'grunnprinsipper', 'IKT-sikkerhet', 'NIS2', 'digital sikkerhet')" },
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
          description: "Filter by document status. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
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
        reference: { type: "string", description: "NSM document reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "no_cyber_search_advisories",
    description:
      "Search NorCERT security advisories and vulnerability alerts. Returns advisories with severity, affected products, and CVE references.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'kritisk sarbarhet', 'ransomware')" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "no_cyber_get_advisory",
    description: "Get a specific NorCERT security advisory by reference.",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "NorCERT advisory reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "no_cyber_list_frameworks",
    description:
      "List all NSM frameworks and standard series covered in this MCP.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "no_cyber_about",
    description: "Norwegian Cybersecurity MCP server. Covers NSM Grunnprinsipper for IKT-sikkerhet, NorCERT advisories, and digital security guidance.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "no_cyber_list_sources",
    description:
      "List all data sources covered by this MCP with official URLs and provenance metadata.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "no_cyber_check_data_freshness",
    description:
      "Check the freshness of the underlying data. Returns coverage date, record counts per source, and whether the data is stale (older than 90 days).",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

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

// --- Helpers -----------------------------------------------------------------

function responseMeta() {
  return {
    disclaimer:
      "This data is sourced from NSM (Nasjonal sikkerhetsmyndighet) and NorCERT public publications. Provided for informational purposes only and may not reflect the latest official guidance.",
    data_age: "2026-04-04",
    copyright: "NSM / NorCERT — Norwegian government public domain",
    source_url: "https://nsm.no/",
  };
}

function textContent(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

function notFoundContent(error: string) {
  return textContent({ error, _error_type: "not_found", _meta: responseMeta() });
}

// --- MCP server factory ------------------------------------------------------

function createMcpServer(): Server {
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
          const resultsWithCitation = results.map((item) => ({
            ...item,
            _citation: {
              canonical_ref: item.reference,
              display_text: `${item.title} (${item.reference})`,
              lookup: { tool: "no_cyber_get_guidance", args: { reference: item.reference } },
            },
          }));
          return textContent({ results: resultsWithCitation, count: results.length, _meta: responseMeta() });
        }

        case "no_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return notFoundContent(`Guidance document not found: ${parsed.reference}`);
          }
          return textContent({
            ...doc,
            _citation: {
              canonical_ref: doc.reference,
              display_text: `${doc.title} (${doc.reference})`,
              lookup: { tool: "no_cyber_get_guidance", args: { reference: doc.reference } },
            },
            _meta: responseMeta(),
          });
        }

        case "no_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          const resultsWithCitation = results.map((item) => ({
            ...item,
            _citation: {
              canonical_ref: item.reference,
              display_text: `${item.title} (${item.reference})`,
              lookup: { tool: "no_cyber_get_advisory", args: { reference: item.reference } },
            },
          }));
          return textContent({ results: resultsWithCitation, count: results.length, _meta: responseMeta() });
        }

        case "no_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return notFoundContent(`Advisory not found: ${parsed.reference}`);
          }
          return textContent({
            ...advisory,
            _citation: {
              canonical_ref: advisory.reference,
              display_text: `${advisory.title} (${advisory.reference})`,
              lookup: { tool: "no_cyber_get_advisory", args: { reference: advisory.reference } },
            },
            _meta: responseMeta(),
          });
        }

        case "no_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({ frameworks, count: frameworks.length, _meta: responseMeta() });
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
            _meta: responseMeta(),
          });
        }

        case "no_cyber_list_sources": {
          type CoverageSource = {
            id: string;
            name: string;
            url: string;
            authority: string;
            item_count: number;
            item_type: string;
            last_refresh: string;
            refresh_frequency: string;
          };
          type CoverageFile = { sources?: CoverageSource[] };
          let coverage: CoverageFile = {};
          try {
            coverage = JSON.parse(readFileSync(join(DATA_DIR, "coverage.json"), "utf8")) as CoverageFile;
          } catch {
            // fallback to hardcoded below
          }
          const sources: CoverageSource[] = coverage.sources ?? [
            {
              id: "nsm",
              name: "NSM (Nasjonal sikkerhetsmyndighet)",
              url: "https://nsm.no",
              authority: "NSM",
              item_count: 186,
              item_type: "guidance",
              last_refresh: "2026-04-04",
              refresh_frequency: "quarterly",
            },
            {
              id: "norcert",
              name: "NorCERT (Norwegian CERT)",
              url: "https://nsm.no/fagomrader/operativt-samarbeid/norcert/",
              authority: "NSM / NorCERT",
              item_count: 98,
              item_type: "advisory",
              last_refresh: "2026-04-04",
              refresh_frequency: "quarterly",
            },
            {
              id: "frameworks",
              name: "NSM Framework Series",
              url: "https://nsm.no",
              authority: "NSM",
              item_count: 17,
              item_type: "framework",
              last_refresh: "2026-04-04",
              refresh_frequency: "quarterly",
            },
          ];
          return textContent({ sources, count: sources.length, _meta: responseMeta() });
        }

        case "no_cyber_check_data_freshness": {
          type CoverageFile = {
            coverage_date?: string;
            summary?: { total_items?: number };
            sources?: Array<{ id: string; item_count: number }>;
          };
          let coverage: CoverageFile = {};
          try {
            coverage = JSON.parse(readFileSync(join(DATA_DIR, "coverage.json"), "utf8")) as CoverageFile;
          } catch {
            // fallback to defaults
          }
          const asOf = coverage.coverage_date ?? "2026-04-04";
          const ageDays = Math.floor((Date.now() - new Date(asOf).getTime()) / (1000 * 60 * 60 * 24));
          const recordCounts = coverage.sources
            ? Object.fromEntries(coverage.sources.map((s) => [s.id, s.item_count]))
            : { nsm: 186, norcert: 98, frameworks: 17 };
          return textContent({
            as_of: asOf,
            age_days: ageDays,
            record_counts: recordCounts,
            total_items: coverage.summary?.total_items ?? 301,
            is_stale: ageDays > 90,
            _meta: responseMeta(),
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

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
