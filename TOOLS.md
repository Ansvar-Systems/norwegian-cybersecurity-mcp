# Tools -- Norwegian Cybersecurity MCP

6 tools for searching and retrieving Norwegian cybersecurity guidance, NorCERT advisories, and NSM frameworks.

Most data is in Norwegian (Bokmal). Tool descriptions and parameter names are in English.

---

## 1. no_cyber_search_guidance

Full-text search across NSM cybersecurity guidance, Grunnprinsipper for IKT-sikkerhet, and digital security recommendations. Returns matching documents with reference, title, series, and summary.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | Yes | Search query (e.g., `grunnprinsipper`, `IKT-sikkerhet`, `NIS2`, `digital sikkerhet`, `trusselrapport`) |
| `type` | string | No | Filter by document type: `guidance`, `grunnprinsipp`, `standard`, `recommendation` |
| `series` | string | No | Filter by NSM series: `NSM`, `NIS2-NO`, `Grunnprinsipper` |
| `status` | string | No | Filter by status: `current`, `superseded`, `draft`. Defaults to all. |
| `limit` | number | No | Maximum results (default 20, max 100) |

**Returns:** Array of matching guidance documents with id, reference, title, title_en, date, type, series, summary, full_text, topics, and status.

**Example:**

```json
{
  "query": "grunnprinsipper IKT-sikkerhet",
  "type": "grunnprinsipp",
  "status": "current"
}
```

**Data sources:** NSM (nsm.no) -- Grunnprinsipper for IKT-sikkerhet, digital security guidance, sikkerhetsloven guidance.

**Limitations:** Seed dataset with 98 guidance documents. Summaries, not full guidance text. Norwegian-language content primarily.

---

## 2. no_cyber_get_guidance

Get a specific NSM guidance document by its reference string. Returns the full record including text, metadata, and topics.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | Yes | NSM document reference (e.g., `NSM-GP-01`) |

**Returns:** Single guidance record with all fields, or an error if not found.

**Example:**

```json
{
  "reference": "NSM-GP-01"
}
```

**Data sources:** NSM (nsm.no).

**Limitations:** Exact match on reference string. Partial matches are not supported -- use `no_cyber_search_guidance` for fuzzy search.

---

## 3. no_cyber_search_advisories

Search NorCERT security advisories and vulnerability alerts. Returns advisories with severity, affected products, and CVE references where available.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | Yes | Search query (e.g., `kritisk sarbarhet`, `ransomware`, `VPN`, `Exchange`) |
| `severity` | string | No | Filter by severity level: `critical`, `high`, `medium`, `low` |
| `limit` | number | No | Maximum results (default 20, max 100) |

**Returns:** Array of matching advisories with id, reference, title, date, severity, affected_products, summary, full_text, and cve_references.

**Example:**

```json
{
  "query": "ransomware",
  "severity": "critical"
}
```

**Data sources:** NorCERT / NSM (nsm.no/fagomrader/operativt-samarbeid/norcert/).

**Limitations:** Seed dataset with 42 advisories. Summaries of advisories, not the full original publications. Norwegian-language content primarily.

---

## 4. no_cyber_get_advisory

Get a specific NorCERT security advisory by its reference string. Returns the full record including severity, affected products, and CVE references.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | Yes | NorCERT advisory reference (e.g., `NCERT-2025-001`) |

**Returns:** Single advisory record with all fields, or an error if not found.

**Example:**

```json
{
  "reference": "NCERT-2025-001"
}
```

**Data sources:** NorCERT / NSM (nsm.no).

**Limitations:** Exact match on reference string. Partial matches are not supported -- use `no_cyber_search_advisories` for fuzzy search.

---

## 5. no_cyber_list_frameworks

List all NSM frameworks and standard series covered in this MCP, including Grunnprinsipper for IKT-sikkerhet, NIS2 implementation guidance, and nasjonal strategi for digital sikkerhet.

**Parameters:** None.

**Returns:** Array of frameworks with id, name, name_en, description, and document_count.

**Example:**

```json
{}
```

**Data sources:** NSM framework metadata.

**Limitations:** None. Returns the full framework list.

---

## 6. no_cyber_about

Return metadata about this MCP server: version, description, data sources, coverage summary, and tool list. Takes no parameters.

**Parameters:** None.

**Returns:** Server name, version, description, data_source, coverage summary (guidance, advisories, frameworks), and tool list (name, description).

**Example:**

```json
{}
```

**Data sources:** N/A (server metadata).

**Limitations:** None.
