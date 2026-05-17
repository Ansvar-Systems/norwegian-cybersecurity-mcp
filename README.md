# Norwegian Cybersecurity MCP

<!-- ANSVAR-CTA-BEGIN -->
> ### ▶ Try this MCP instantly via Ansvar Gateway
> **50 free queries/day · no card required · OAuth signup at [ansvar.eu/gateway](https://ansvar.eu/gateway)**
>
> One endpoint, one OAuth signup, access from any MCP-compatible client.

### Connect

**Claude Code** (one line):

```bash
claude mcp add ansvar --transport http https://gateway.ansvar.eu/mcp
```

**Claude Desktop / Cursor** — add to `claude_desktop_config.json` (or `mcp.json`):

```json
{
  "mcpServers": {
    "ansvar": {
      "type": "url",
      "url": "https://gateway.ansvar.eu/mcp"
    }
  }
}
```

**Claude.ai** — Settings → Connectors → Add custom connector → paste `https://gateway.ansvar.eu/mcp`

First request opens an OAuth flow at [ansvar.eu/gateway](https://ansvar.eu/gateway). After signup, your client is bound to your account; tier (free / premium / team / company) determines fan-out, quota, and which downstream MCPs are reachable.

---

## Self-host this MCP

You can also clone this repo and build the corpus yourself. The schema,
fetcher, and tool implementations all live here. What is not in the repo is
the pre-built database — TDM and standards-licensing constraints on the
upstream sources mean we host the corpus on Ansvar infrastructure rather
than redistribute it as a public artifact.

Build your own: run this repo's ingestion script (entry-point varies per
repo — typically `scripts/ingest.sh`, `npm run ingest`, or `make ingest`;
check the repo root).
<!-- ANSVAR-CTA-END -->


MCP server for Norwegian cybersecurity guidance -- NSM Grunnprinsipper for IKT-sikkerhet, NorCERT security advisories, and digital security frameworks.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Covers NSM (Nasjonal sikkerhetsmyndighet) guidance and NorCERT advisories with full-text search across 150 records. Most data is in Norwegian (Bokmal).

Built by [Ansvar Systems](https://ansvar.eu) -- Stockholm, Sweden

---

## Sources Covered

| Source | Role | Website |
|--------|------|---------|
| **NSM (Nasjonal sikkerhetsmyndighet)** | Norwegian National Security Authority -- cybersecurity guidance, Grunnprinsipper for IKT-sikkerhet, sikkerhetsloven implementation | [nsm.no](https://nsm.no) |
| **NorCERT** | Norwegian CERT -- security advisories, vulnerability alerts, threat assessments | [nsm.no/norcert](https://nsm.no/fagomrader/operativt-samarbeid/norcert/) |

---

## Tools

| Tool | Description |
|------|-------------|
| `no_cyber_search_guidance` | Full-text search across NSM cybersecurity guidance, Grunnprinsipper for IKT-sikkerhet, and digital security recommendations |
| `no_cyber_get_guidance` | Get a specific NSM guidance document by reference |
| `no_cyber_search_advisories` | Search NorCERT security advisories and vulnerability alerts |
| `no_cyber_get_advisory` | Get a specific NorCERT advisory by reference |
| `no_cyber_list_frameworks` | List all NSM frameworks and standard series covered |
| `no_cyber_about` | Return server metadata: version, sources, tool list, data coverage |

Full tool documentation: [TOOLS.md](TOOLS.md)

---

## Data Coverage

| Source | Records | Content |
|--------|---------|---------|
| NSM guidance | 98 documents | Grunnprinsipper for IKT-sikkerhet (21 principles, v2.1), digital security guidance, NIS2 implementation, risk assessment, incident response |
| NorCERT advisories | 42 advisories | Security advisories, vulnerability alerts, CVE references, severity ratings |
| Frameworks | 10 entries | Grunnprinsipper, NIS2-NO, nasjonal strategi for digital sikkerhet, sikkerhetsloven guidance |
| **Total** | **150 records** | ~428 KB database |

**Language note:** Most content is in Norwegian (Bokmal). Some records include English titles. Search queries work best in Norwegian (e.g., `grunnprinsipper`, `IKT-sikkerhet`, `sarbarhet`, `tilgangsstyring`).

Full coverage details: [COVERAGE.md](COVERAGE.md)

---

## Data Sources

See [sources.yml](sources.yml) for machine-readable provenance metadata.

---

## Docker

```bash
docker build -t norwegian-cybersecurity-mcp .
docker run --rm -p 3000:3000 -v /path/to/data:/app/data norwegian-cybersecurity-mcp
```

Set `NO_CYBER_DB_PATH` to use a custom database location (default: `data/no-cyber.db`).

---

## Development

```bash
npm install
npm run build
npm run seed         # populate sample data
npm run dev          # HTTP server on port 3000
```

---

## Further Reading

- [TOOLS.md](TOOLS.md) -- full tool documentation with examples
- [COVERAGE.md](COVERAGE.md) -- data coverage and limitations
- [sources.yml](sources.yml) -- data provenance metadata
- [DISCLAIMER.md](DISCLAIMER.md) -- legal disclaimer
- [PRIVACY.md](PRIVACY.md) -- privacy policy
- [SECURITY.md](SECURITY.md) -- vulnerability disclosure

---

## License

Apache-2.0 -- [Ansvar Systems AB](https://ansvar.eu)

See [LICENSE](LICENSE) for the full license text.

See [DISCLAIMER.md](DISCLAIMER.md) for important legal disclaimers about the use of this cybersecurity guidance data.

---

[ansvar.ai/mcp](https://ansvar.ai/mcp) -- Full MCP server catalog
