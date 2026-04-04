/**
 * Seed the NSM (Nasjonal sikkerhetsmyndighet) database with sample guidance,
 * advisories, and frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["NO_CYBER_DB_PATH"] ?? "data/no-cyber.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted existing database at ${DB_PATH}`); }

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow { id: string; name: string; name_en: string; description: string; document_count: number; }

const frameworks: FrameworkRow[] = [
  { id: "grunnprinsipper", name: "Grunnprinsipper for IKT-sikkerhet", name_en: "Basic Principles for ICT Security",
    description: "NSMs grunnprinsipper for IKT-sikkerhet gir anbefalinger for a beskytte IKT-systemer. Dekker fire kategorier: identifisere, beskytte, oppdage og handtere.",
    document_count: 5 },
  { id: "nis2-no", name: "NIS2 i Norge", name_en: "NIS2 Directive Implementation in Norway",
    description: "NSM er nasjonalt kontaktpunkt for NIS2-direktivet i Norge gjennom EOS-samarbeidet. Veiledning for virksomheter som er omfattet av NIS2.",
    document_count: 2 },
  { id: "nasjonal-strategi", name: "Nasjonal strategi for digital sikkerhet", name_en: "National Strategy for Digital Security",
    description: "Regjeringens strategi for digital sikkerhet i Norge. NSM har en sentral rolle i gjennomforingen, spesielt innen forebyggende sikkerhet og hendelseshandtering via NorCERT.",
    document_count: 2 },
];

const insertFramework = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) { insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count); }
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow { reference: string; title: string; title_en: string; date: string; type: string; series: string; summary: string; full_text: string; topics: string; status: string; }

const guidance: GuidanceRow[] = [
  {
    reference: "NSM-GP-2023-001", title: "Grunnprinsipper for IKT-sikkerhet — Identifisere og kartlegge",
    title_en: "Basic Principles for ICT Security — Identify and Map", date: "2023-06-15",
    type: "grunnprinsipp", series: "Grunnprinsipper",
    summary: "NSMs grunnprinsipper for kategorien Identifisere. Dekker kartlegging av verdier, leverandorer, IKT-infrastruktur, brukere og sarbarheter. Grunnlaget for alle andre sikkerhetstiltak.",
    full_text: "Grunnprinsippet Identifisere og kartlegge er fundamentet i NSMs rammeverk for IKT-sikkerhet. Organisasjoner ma ha oversikt over hva de skal beskytte for a kunne beskytte det effektivt. Kartlegg verdier: Identifiser virksomhetens viktigste informasjon, systemer og tjenester. Klassifiser etter konfidensialitet, integritet og tilgjengelighet. Kartlegg leverandorer: Ha oversikt over alle IKT-leverandorer og deres tilgang til virksomhetens systemer og data. Vurder leverandorenes sikkerhetsmodenhet. Kartlegg IKT-infrastruktur: Dokumenter alle systemer, nettverk, tjenester og dataflyt. Hold oversikten oppdatert. Kartlegg brukere: Ha oversikt over alle brukere og deres tilganger. Gjennomfor jevnlige tilgangsgjennomganger. Kartlegg sarbarheter: Gjennomfor jevnlige sarbarhetsanalyser og penetrasjonstester. Prioriter utbedring basert pa risiko. NSM anbefaler at kartleggingen gjennomfores minimum arlig og ved vesentlige endringer i IKT-infrastrukturen.",
    topics: JSON.stringify(["identifisere", "kartlegging", "verdier", "leverandorer", "sarbarheter"]), status: "current",
  },
  {
    reference: "NSM-GP-2023-002", title: "Grunnprinsipper for IKT-sikkerhet — Beskytte og opprettholde",
    title_en: "Basic Principles for ICT Security — Protect and Maintain", date: "2023-06-15",
    type: "grunnprinsipp", series: "Grunnprinsipper",
    summary: "NSMs grunnprinsipper for kategorien Beskytte. Dekker tilgangskontroll, sikker konfigurasjon, sikkerhetskopier, nettverkssikkerhet og opplaering.",
    full_text: "Grunnprinsippet Beskytte og opprettholde dekker tiltak for a hindre uonskede hendelser i IKT-systemer. Tilgangskontroll: Implementer prinsippet om minste privilegium. Bruk flerfaktorautentisering (MFA) for alle brukere, spesielt for tilgang til kritiske systemer og fjerntilgang. Sikker konfigurasjon: Bruk NSMs anbefalte sikkerhetskonfigurasjoner. Fjern unodvendig programvare og tjenester. Oppdater systemer jevnlig med sikkerhetsoppdateringer. Sikkerhetskopier: Ta jevnlige sikkerhetskopier av alle viktige data og systemer. Test gjenoppretting regelmessig. Oppbevar kopier offline og geografisk atskilt. Nettverkssikkerhet: Segmenter nettverk for a begrense skadevirkninger ved angrep. Implementer brannmurer og overvak nettverkstrafikk. Beskytt traadlose nettverk. Opplaering: Gjennomfor regelmessig sikkerhetsopplaering for alle ansatte. Simuler phishing-angrep for a teste og forbedre bevissthet. NSM understreker at beskyttelsestiltak ma vedlikeholdes loepaende — sikkerhet er en kontinuerlig prosess.",
    topics: JSON.stringify(["beskytte", "tilgangskontroll", "MFA", "sikkerhetskopier", "nettverkssikkerhet"]), status: "current",
  },
  {
    reference: "NSM-GP-2023-003", title: "Grunnprinsipper for IKT-sikkerhet — Oppdage",
    title_en: "Basic Principles for ICT Security — Detect", date: "2023-06-15",
    type: "grunnprinsipp", series: "Grunnprinsipper",
    summary: "NSMs grunnprinsipper for kategorien Oppdage. Dekker logging, overvaking, hendelsesdeteksjon og varsling.",
    full_text: "Grunnprinsippet Oppdage handler om a etablere evne til a oppdage uonskede hendelser i IKT-systemer tidlig. Logging: Aktiver logging pa alle kritiske systemer. Sentral innsamling og lagring av logger. Beskytt logger mot manipulering. Bevar logger i henhold til lovkrav og virksomhetens behov. Overvaking: Overvak nettverkstrafikk for uvanlige monstre. Overvak endepunkter med EDR-verktoy. Overvak tilgangslogger for mistenkelig aktivitet. Hendelsesdeteksjon: Implementer automatisert deteksjon med SIEM-losninger. Bruk NSMs trusselindikatorer (IoC). Abonner pa NorCERTs varsler om aktive trusler. Korreler hendelser pa tvers av systemer for a oppdage avanserte angrep. Varsling: Etabler klare rutiner for hvem som varsles ved sikkerhetshendelser. Integrer med NorCERT for varsling om nasjonale trusler. NSM anbefaler at organisasjoner etablerer et sikkerhetsoperasjonssenter (SOC) eller bruker en ekstern SOC-tjeneste.",
    topics: JSON.stringify(["oppdage", "logging", "overvaking", "SIEM", "SOC"]), status: "current",
  },
  {
    reference: "NSM-GP-2023-004", title: "Grunnprinsipper for IKT-sikkerhet — Handtere og gjenopprette",
    title_en: "Basic Principles for ICT Security — Respond and Recover", date: "2023-06-15",
    type: "grunnprinsipp", series: "Grunnprinsipper",
    summary: "NSMs grunnprinsipper for kategorien Handtere. Dekker hendelseshandtering, kommunikasjon, gjenoppretting og laering etter hendelser.",
    full_text: "Grunnprinsippet Handtere og gjenopprette beskriver hvordan organisasjoner skal reagere pa og gjenopprette etter sikkerhetshendelser. Hendelseshandtering: Ha en oppdatert hendelseshandteringsplan. Definer roller og ansvar for hendelseshandtering. Ov regelmessig med tabletop-ovelser og simulerte hendelser. Kommunikasjon: Etabler kommunikasjonskanaler som fungerer ogsa under angrep. Varsle NorCERT ved alvorlige hendelser — dette er lovpalagt for virksomheter underlagt sikkerhetsloven. Informer ledelsen og berorte parter. Gjenoppretting: Gjenopprett fra verifiserte sikkerhetskopier. Prioriter gjenoppretting av virksomhetskritiske tjenester. Verifiser at trusselen er fjernet for gjenoppretting. Laering: Gjennomfor evaluering etter alle hendelser. Dokumenter laerdommer og oppdater prosedyrer. Del relevante erfaringer med NorCERT og bransjefellesskap. Sikkerhetsloven paragraf 4-5 palegger virksomheter a varsle NSM ved sikkerhetshendelser som kan pavirke nasjonale sikkerhetsinteresser.",
    topics: JSON.stringify(["handtere", "hendelseshandtering", "gjenoppretting", "sikkerhetsloven", "NorCERT"]), status: "current",
  },
  {
    reference: "NSM-2024-001", title: "Risiko 2024 — NSMs sikkerhetsfaglige rad",
    title_en: "Risk 2024 — NSM's Security Advisory", date: "2024-02-15",
    type: "recommendation", series: "NSM",
    summary: "NSMs arlige rapport om sikkerhetsfaglige rad og trusselbildet mot Norge. Dekker cybertrusler fra statlige aktorer, sikkerhetspolitisk situasjon og anbefalinger for norske virksomheter og myndigheter.",
    full_text: "NSMs rapport Risiko 2024 gir en samlet vurdering av trusler og risikoer mot nasjonal sikkerhet i det digitale rommet. Trusselbildet: Russland utgjor den storste trusselen mot Norge i det digitale rommet. Kinesisk etterretning retter seg mot norsk teknologi, forsvar og maritim sektor. Nordkoreanske aktorer finansierer regimet gjennom kryptovaluta-tyveri. Cyberkriminalitet: Ransomware er fortsatt den storste trusselen mot norske virksomheter. LockBit, ALPHV/BlackCat og Cl0p-gruppen har rammet norske virksomheter. Angrep mot leverandorkjeder oker i omfang. Kritisk infrastruktur: Truslen mot norsk kritisk infrastruktur er hoy. Energisektoren, petroleumssektoren og elektronisk kommunikasjon er saerlig utsatt. Anbefalinger: NSM anbefaler at alle virksomheter folger Grunnprinsipper for IKT-sikkerhet. Implementer NIS2-krav i forkant av norsk lovgivning. Styrk samarbeid med NorCERT og sektordialog. Investering i sikkerhetskompetanse og -kultur er avgjorende.",
    topics: JSON.stringify(["trusselrapport", "risiko", "cyberspionage", "ransomware", "kritisk-infrastruktur"]), status: "current",
  },
];

const insertGuidance = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
const insertGuidanceAll = db.transaction(() => { for (const g of guidance) { insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); } });
insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow { reference: string; title: string; date: string; severity: string; affected_products: string; summary: string; full_text: string; cve_references: string; }

const advisories: AdvisoryRow[] = [
  {
    reference: "NORCERT-ADV-2024-001", title: "Kritisk sarbarhet i Ivanti Connect Secure — aktivt utnyttet",
    date: "2024-01-15", severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure", "VPN-losninger"]),
    summary: "NorCERT varsler om aktiv utnyttelse av kritiske sarbarheter i Ivanti Connect Secure VPN-losninger (CVE-2024-21887, CVE-2023-46805). Norske virksomheter med eksponerte Ivanti-systemer ma iverksette tiltak umiddelbart.",
    full_text: "NorCERT har observert aktiv utnyttelse av to sarbarheter i Ivanti Connect Secure som nar de kombineres gir uautentisert fjernkjoering av kode (RCE). CVE-2023-46805 (CVSS 8.2): Autentiserings-bypass i webkomponenten. CVE-2024-21887 (CVSS 9.1): Kommandoinjeksjon i webkomponenten. Sarberetene utnyttes aktivt av statlige aktorer. NSM har bekreftet utnyttelse mot norske virksomheter. Umiddelbare tiltak: (1) Gjennomfor Ivantiis integritetskontrollverktoy (ICT) for a oppdage kompromittering. (2) Implementer Ivantiis midlertidige losning (mitigation) umiddelbart. (3) Installer oppdatering nar tilgjengelig fra Ivanti. (4) Overvak nettverkstrafikk fra VPN-konsentratorer for uvanlig aktivitet. (5) Gjennomga tilgangslogger for tegn pa uautorisert tilgang. Varsling: Virksomheter som mistaenker kompromittering skal varsle NorCERT pa varsle@cert.no.",
    cve_references: JSON.stringify(["CVE-2024-21887", "CVE-2023-46805"]),
  },
  {
    reference: "NORCERT-ADV-2024-002", title: "Okt DDoS-trussel mot norske mal fra pro-russiske grupper",
    date: "2024-03-10", severity: "high",
    affected_products: JSON.stringify(["Offentlige myndigheter", "Kritisk infrastruktur", "Finanssektor"]),
    summary: "NorCERT varsler om okt DDoS-aktivitet mot norske malsettinger fra pro-russiske hacktivistgrupper. Angrepene er knyttet til Norges stotte til Ukraina og NATO-medlemskap. Norske virksomheter bor teste DDoS-beredskap.",
    full_text: "NorCERT har registrert en markant okning i DDoS-angrep (Distributed Denial of Service) mot norske virksomheter og offentlige myndigheter. Trusselaktorer: Pro-russiske hacktivistgrupper som NoName057(16) og KillNet koordinerer angrep via Telegram. Angrepene er motivert av Norges stotte til Ukraina og NATO-politikk. Malutvalg: Offentlige myndigheters nettsider, bank- og finanssektoren, transportinfrastruktur (Avinor, NSB/Vy), medieorganisasjoner. Angrepskarakteristikk: Volumetriske DDoS-angrep typisk mellom 10 og 100+ Gbps. Angrepene varer vanligvis 2-6 timer. Noen angrep kombinerer volumetriske og applikasjonslags-teknikker. Anbefalte tiltak: Verifiser at DDoS-beskyttelse er aktivert og korrekt konfigurert. Test beredskapsplaner for DDoS-hendelser. Etabler kontakt med internettleverandoren om DDoS-responsrutiner. Sikre at kritiske tjenester har alternative tilgangsveger. Varsle NorCERT om DDoS-angrep.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NORCERT-ADV-2024-003", title: "Sarbarheter i FortiOS — aktiv utnyttelse i Norge",
    date: "2024-02-20", severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS", "FortiGate brannmurer", "FortiProxy"]),
    summary: "NorCERT varsler om aktiv utnyttelse av sarbarheter i Fortinet FortiOS (CVE-2024-21762) mot norske virksomheter. Sarbarheten muliggjor fjernkjoering av kode uten autentisering. Norske virksomheter med FortiGate-brannmurer ma oppdatere umiddelbart.",
    full_text: "En kritisk sarbarhet (CVE-2024-21762, CVSS 9.6) i Fortinet FortiOS utnyttes aktivt mot norske virksomheter. Sarbarheten er i SSL VPN-funksjonaliteten og muliggjor uautentisert fjernkjoering av kode via spesialkonstruerte HTTP-foresporsler. NSM/NorCERT har bekreftet kompromittering av norske FortiGate-brannmurer. Pavirket: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14, 6.2.0-6.2.15 og FortiProxy 7.4.0-7.4.2, 7.2.0-7.2.8, 7.0.0-7.0.14. Umiddelbare tiltak: (1) Oppdater til siste FortiOS-versjon. (2) Hvis oppdatering ikke er mulig, deaktiver SSL VPN-funksjonaliteten som midlertidig tiltak. (3) Gjennomga logger for tegn pa utnyttelse — se etter uvanlige HTTP-foresporsler mot /remote/. (4) Sjekk om ukjente administratorkontoer er opprettet. (5) Hvis kompromittering mistaenkes, varsle NorCERT og isoler systemet. Varsling: varsle@cert.no eller tlf 02497.",
    cve_references: JSON.stringify(["CVE-2024-21762"]),
  },
];

const insertAdvisory = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
const insertAdvisoriesAll = db.transaction(() => { for (const a of advisories) { insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); } });
insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log("\nDatabase summary:");
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);
db.close();
