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
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
          const annotated = results.map((item) => ({
            ...item,
            _citation: buildCitation({
              canonicalRef: item.reference,
              displayText: item.title,
              toolName: "no_cyber_get_guidance",
              toolArgs: { reference: item.reference },
              attribution: { source_url: item.source_url ?? "", publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
            }),
          }));
          return textContent({ results: annotated, count: annotated.length });
        }

        case "no_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return errorContent(`Guidance document not found: ${parsed.reference}`);
          }
          return textContent({
            ...doc,
            _citation: buildCitation({
              canonicalRef: doc.reference,
              displayText: doc.title,
              toolName: "no_cyber_get_guidance",
              toolArgs: { reference: parsed.reference },
              attribution: { source_url: doc.source_url ?? "", publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
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
          const annotated = results.map((item) => ({
            ...item,
            _citation: buildCitation({
              canonicalRef: item.reference,
              displayText: item.title,
              toolName: "no_cyber_get_advisory",
              toolArgs: { reference: item.reference },
              attribution: { source_url: item.source_url ?? "", publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
            }),
          }));
          return textContent({ results: annotated, count: annotated.length });
        }

        case "no_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return errorContent(`Advisory not found: ${parsed.reference}`);
          }
          return textContent({
            ...advisory,
            _citation: buildCitation({
              canonicalRef: advisory.reference,
              displayText: advisory.title,
              toolName: "no_cyber_get_advisory",
              toolArgs: { reference: parsed.reference },
              attribution: { source_url: advisory.source_url ?? "", publisher: "Nasjonal sikkerhetsmyndighet (NSM)", license: "Public-Domain" },
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
