# Norwegian Cybersecurity MCP

MCP server for Norwegian cybersecurity guidance -- NSM Grunnprinsipper for IKT-sikkerhet, NorCERT security advisories, and digital security frameworks.

[![npm version](https://badge.fury.io/js/@ansvar%2Fnorwegian-cybersecurity-mcp.svg)](https://www.npmjs.com/package/@ansvar/norwegian-cybersecurity-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Covers NSM (Nasjonal sikkerhetsmyndighet) guidance and NorCERT advisories with full-text search across 301 records. Most data is in Norwegian (Bokmal).

Built by [Ansvar Systems](https://ansvar.eu) -- Stockholm, Sweden

---

## Sources Covered

| Source | Role | Website |
|--------|------|---------|
| **NSM (Nasjonal sikkerhetsmyndighet)** | Norwegian National Security Authority -- cybersecurity guidance, Grunnprinsipper for IKT-sikkerhet, sikkerhetsloven implementation | [nsm.no](https://nsm.no) |
| **NorCERT** | Norwegian CERT -- security advisories, vulnerability alerts, threat assessments | [nsm.no/norcert](https://nsm.no/fagomrader/operativt-samarbeid/norcert/) |

---

## Quick Start

### Use Remotely (No Install Needed)

**Endpoint:** `https://mcp.ansvar.eu/norwegian-cybersecurity/mcp` *(deployment pending — use local npm install until confirmed live)*

| Client | How to Connect |
|--------|---------------|
| **Claude Desktop** | Add to `claude_desktop_config.json` (see below) |
| **Claude Code** | `claude mcp add norwegian-cybersecurity --transport http https://mcp.ansvar.eu/norwegian-cybersecurity/mcp` |

**Claude Desktop** -- add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "norwegian-cybersecurity": {
      "type": "url",
      "url": "https://mcp.ansvar.eu/norwegian-cybersecurity/mcp"
    }
  }
}
```

### Use Locally (npm)

```bash
npx @ansvar/norwegian-cybersecurity-mcp
```

Or add to Claude Desktop config for stdio:

```json
{
  "mcpServers": {
    "norwegian-cybersecurity": {
      "command": "npx",
      "args": ["-y", "@ansvar/norwegian-cybersecurity-mcp"]
    }
  }
}
```

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
| `no_cyber_list_sources` | List all data sources with official URLs and provenance metadata |
| `no_cyber_check_data_freshness` | Check data age and whether a refresh is needed (stale if > 90 days) |

Full tool documentation: [TOOLS.md](TOOLS.md)

---

## Data Coverage

| Source | Records | Content |
|--------|---------|---------|
| NSM guidance | 186 documents | Grunnprinsipper for IKT-sikkerhet (21 principles, v2.1), digital security guidance, NIS2 implementation, risk assessment, incident response |
| NorCERT advisories | 98 advisories | Security advisories, vulnerability alerts, CVE references, severity ratings |
| Frameworks | 17 entries | Grunnprinsipper, NIS2-NO, nasjonal strategi for digital sikkerhet, sikkerhetsloven guidance |
| **Total** | **301 records** | ~628 KB database |

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
