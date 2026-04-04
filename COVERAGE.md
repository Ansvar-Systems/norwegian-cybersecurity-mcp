# Coverage -- Norwegian Cybersecurity MCP

Current coverage of Norwegian cybersecurity guidance data from NSM and NorCERT.

**Last updated:** 2026-04-04

---

## Sources

| Source | Authority | Records | Content |
|--------|-----------|---------|---------|
| **NSM (Nasjonal sikkerhetsmyndighet)** | Norwegian National Security Authority | 186 guidance + 17 frameworks | Grunnprinsipper for IKT-sikkerhet (v2.1), digital sikkerhet guidance, NIS2 implementation, sikkerhetsloven guidance |
| **NorCERT** | Norwegian CERT (part of NSM) | 98 advisories | Security advisories, vulnerability alerts, threat assessments |
| **Total** | | **301 records** | 628 KB SQLite database |

---

## Guidance Documents (186)

| Type | Norwegian Term | Count | Description |
|------|----------------|-------|-------------|
| `grunnprinsipp` | Grunnprinsipp | 21 | Grunnprinsipper for IKT-sikkerhet v2.1 -- NSM's foundational ICT security principles |
| `guidance` | Veiledning | ~85 | NSM guidance on digital security, risk management, access control, incident response |
| `standard` | Standard | ~40 | Norwegian cybersecurity standards and baseline requirements |
| `recommendation` | Anbefaling | ~40 | NSM recommendations on specific security topics (e.g., cloud security, mobile security) |

## Frameworks (17)

| Framework | Description |
|-----------|-------------|
| **Grunnprinsipper for IKT-sikkerhet** | NSM's 21 foundational ICT security principles (v2.1) |
| **NIS2-NO** | Norwegian implementation guidance for the NIS2 Directive |
| **Nasjonal strategi for digital sikkerhet** | National strategy for digital security |
| **Sikkerhetsloven** | Security Act implementation guidance |
| **NSM Risikovurdering** | NSM risk assessment methodology |
| **NSM Beredskap** | Emergency preparedness and incident response frameworks |
| **Nasjonal sikkerhetsstrategi** | National security strategy |
| **Rammeverk for hendelseshandtering** | Incident response framework |
| **Rammeverk for leverandorsikkerhet** | Supply chain security framework |
| **Rammeverk for skytjenester** | Cloud services security framework |
| **Rammeverk for IoT-sikkerhet** | IoT security framework |
| + 6 additional framework series | Various NSM publication series |

## NorCERT Advisories (98)

| Severity | Count | Description |
|----------|-------|-------------|
| `critical` | ~18 | Critical vulnerabilities requiring immediate action |
| `high` | ~35 | High-severity threats and vulnerabilities |
| `medium` | ~28 | Medium-severity security advisories |
| `low` | ~17 | Low-severity informational advisories |

Advisories include CVE references where available, affected products, and recommended mitigations.

---

## What Is NOT Included

The following are not covered:

- **Full guidance text** -- records contain summaries, not the complete official text from nsm.no
- **Classified material** -- NSM classified documents (UGRADERT and above) are not included; only publicly available guidance
- **EU cybersecurity directives** -- NIS2 Directive, Cyber Resilience Act, DORA, etc. are covered by the [EU Regulations MCP](https://github.com/Ansvar-Systems/EU_compliance_MCP), not this server
- **Sector-specific regulations** -- detailed financial, health, or energy sector cybersecurity rules are covered by dedicated MCPs
- **Real-time threat intelligence** -- current NorCERT threat feeds and live indicators of compromise are not included
- **Municipality and county security policies** -- local government (kommune/fylkeskommune) security publications are not covered
- **Historical/superseded guidance** -- limited to current versions; superseded NSM publications are mostly excluded
- **NSM samtykker (approvals)** -- NSM approval decisions under sikkerhetsloven are not included
- **Nasjonal sikkerhetsmyndighets arsrapporter** -- NSM annual reports are not included as separate records

---

## Limitations

- **Norwegian text primarily** -- most content is in Norwegian (Bokmal). Some records include English titles. English search queries may return limited results.
- **Summaries, not full guidance text** -- records contain representative summaries, not the complete official text from nsm.no.
- **Manual refresh** -- data is updated manually. Recent NSM publications or NorCERT advisories may not be reflected.
- **No real-time tracking** -- updates and supersessions are not tracked automatically.

---

## Planned Improvements

Automated ingestion is planned from:

- **lovdata.no** -- sikkerhetsloven, forskrift om digital sikkerhet, and related legislation
- **digdir.no** -- Digitaliseringsdirektoratet security standards for public sector

---

## Language

Most content is in Norwegian (Bokmal). The following search terms are useful starting points:

| Norwegian Term | English Equivalent |
|----------------|-------------------|
| IKT-sikkerhet | ICT security |
| grunnprinsipper | foundational principles |
| digital sikkerhet | digital security |
| trusselrapport | threat report |
| sarbarhet | vulnerability |
| tilgangsstyring | access control |
| hendelseshandtering | incident response |
| risikovurdering | risk assessment |
| beredskap | emergency preparedness |
| sikkerhetsloven | the Security Act |
| leverandorsikkerhet | supply chain security |
| skytjenester | cloud services |
| ransomware | ransomware |
| personvern | privacy / data protection |
| autentisering | authentication |
| kryptering | encryption |
