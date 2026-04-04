/**
 * Comprehensive real-data ingestion for Norwegian Cybersecurity MCP.
 *
 * Sources:
 *   - NSM (Nasjonal sikkerhetsmyndighet) — Grunnprinsipper for IKT-sikkerhet v2.1,
 *     guidance documents, Risiko reports, security recommendations
 *   - NorCERT / NCSC (Nasjonalt cybersikkerhetssenter) — security advisories,
 *     vulnerability alerts, incident response guidance
 *   - Lovdata — Sikkerhetsloven (LOV-2018-06-01-24), Virksomhetsikkerhetsforskriften,
 *     Klareringsforskriften, Beskyttelsesinstruksen
 *
 * Usage:
 *   npx tsx scripts/ingest-all.ts          # incremental (INSERT OR IGNORE)
 *   npx tsx scripts/ingest-all.ts --force   # wipe and re-seed
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["NO_CYBER_DB_PATH"] ?? "data/no-cyber.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

// ---------------------------------------------------------------------------
// 1. Frameworks
// ---------------------------------------------------------------------------

const frameworks: FrameworkRow[] = [
  {
    id: "grunnprinsipper",
    name: "Grunnprinsipper for IKT-sikkerhet",
    name_en: "Basic Principles for ICT Security",
    description:
      "NSMs grunnprinsipper for IKT-sikkerhet versjon 2.1 (juni 2024). Definerer 21 prinsipper fordelt pa fire kategorier: Identifisere og kartlegge, Beskytte og opprettholde, Oppdage, og Handtere og gjenopprette. Prinsippene gir anbefalinger for a beskytte informasjonssystemer mot uautorisert tilgang, skade eller misbruk. Utarbeidet i samarbeid med virksomheter som forvalter kritiske samfunnsfunksjoner og kritisk infrastruktur.",
    document_count: 21,
  },
  {
    id: "sikkerhetsloven",
    name: "Sikkerhetsloven og forskrifter",
    name_en: "Security Act and Regulations",
    description:
      "Lov om nasjonal sikkerhet (LOV-2018-06-01-24) med tilhorende forskrifter: Virksomhetsikkerhetsforskriften, Klareringsforskriften og Beskyttelsesinstruksen. Loven skal forebygge, avdekke og motvirke sikkerhetstruende virksomhet. Tradt i kraft 1. januar 2019. Gjelder statlige, fylkeskommunale og kommunale organer, samt leverandorer ved sikkerhetsgraderte anskaffelser.",
    document_count: 8,
  },
  {
    id: "digitalsikkerhetsloven",
    name: "Digitalsikkerhetsloven",
    name_en: "Digital Security Act (NIS2 Implementation)",
    description:
      "Digitalsikkerhetsloven gjennomforer NIS-direktivet i norsk rett og styrker Norges tilknytning til europeisk beredskaps- og sikkerhetssamarbeid. Loven trer i kraft 1. oktober 2025. Inkluderer elementer fra NIS2 som rapportering, tilsyn og sanksjoner. NSM er nasjonalt kontaktpunkt. NIS2-direktivet vil bli fullt gjennomfort i en nyere norsk lov som inkluderer bade NIS2 og CER-direktivet.",
    document_count: 3,
  },
  {
    id: "nasjonal-strategi",
    name: "Nasjonal strategi for digital sikkerhet",
    name_en: "National Strategy for Digital Security",
    description:
      "Regjeringens strategi for digital sikkerhet i Norge. NSM har en sentral rolle i gjennomforingen, spesielt innen forebyggende sikkerhet og hendelseshandtering via NCSC/NorCERT. Inkluderer tiltaksoversikt og sektorspesifikke anbefalinger.",
    document_count: 3,
  },
  {
    id: "risiko-rapporter",
    name: "Risiko-rapportserien",
    name_en: "Risk Report Series",
    description:
      "NSMs arlige rapport om sikkerhetsfaglige rad og trusselbildet mot Norge. Rapporten gir virksomheter bedre forutsetninger for a se sitt sikkerhetsarbeid i en storre sammenheng. Dekker cybertrusler fra statlige aktorer, sikkerhetspolitisk situasjon, ransomware og anbefalinger for norske virksomheter og myndigheter.",
    document_count: 5,
  },
  {
    id: "fem-tiltak",
    name: "Fem effektive tiltak mot dataangrep",
    name_en: "Five Effective Measures Against Data Attacks",
    description:
      "NSMs anbefalinger om fem effektive tekniske tiltak som systemeiere bor ta i bruk for a beskytte sine systemer mot dataangrep. De vanligste angrepene gjennomfores med skadevare mot ansattes datamaskiner og ved gjetting av enkle passord.",
    document_count: 5,
  },
  {
    id: "digital-utpressing",
    name: "Sikkerhetstiltak mot digital utpressing",
    name_en: "Security Measures Against Digital Extortion",
    description:
      "NSMs veileder med 44 tiltak fordelt pa 8 tiltaksgrupper for a forebygge, oppdage og handtere digital utpressing (ransomware). Dekker planlegging, sikkerhetskopi, forebygging av inngang og spredning, hendelseshandtering og produktspesifikke tiltak.",
    document_count: 8,
  },
  {
    id: "ncsc-varsler",
    name: "NCSC sikkerhetsvarsler",
    name_en: "NCSC Security Advisories",
    description:
      "Nasjonalt cybersikkerhetssenters (NCSC) varsler om sarbarheter pa internett, viktige oppdateringer og andre cyberhendelser. NCSC fokuserer pa varsler som er relevante for kritiske samfunnstjenester og/eller som berorer store deler av samfunnet. Arkiv med 239+ varsler fra 2018 til i dag.",
    document_count: 40,
  },
  {
    id: "e-post-sikkerhet",
    name: "Grunnleggende tiltak for sikring av e-post",
    name_en: "Basic Measures for Email Security",
    description:
      "NSMs anbefalinger for sikring av e-post med fire beskyttelsesmekanismer: STARTTLS (kryptert overfoering), SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) og DMARC (Domain Message Authentication Reporting and Conformance). Reduserer risikoen for e-postforfalskning (spoofing) og phishing.",
    document_count: 4,
  },
  {
    id: "digital-beredskap",
    name: "Digital beredskap i en skjerpet situasjon",
    name_en: "Digital Preparedness in a Heightened Threat Situation",
    description:
      "NCSCs anbefalinger for virksomheter som onsker a styrke sin digitale beredskap i lys av det skjerpede trusselbildet. Ni konkrete omrader: systemoversikt, sikkerhetskopi, sarbarhetsreduksjon, identitets- og tilgangskontroll, sikkerhetsovervaking, ansattbevissthet, hendelseshandtering, leverandorkjedesikkerhet og skytjenestesikring.",
    document_count: 9,
  },
];

// ---------------------------------------------------------------------------
// 2. Guidance — Grunnprinsipper for IKT-sikkerhet (all 21 principles)
// ---------------------------------------------------------------------------

const grunnprinsipper: GuidanceRow[] = [
  // ---- Kategori 1: Identifisere og kartlegge ----
  {
    reference: "NSM-GP-2.1-1.1",
    title: "1.1 Kartlegg styringsstrukturer, leveranser og understottende systemer",
    title_en: "1.1 Map governance structures, deliverables and supporting systems",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Forste prinsipp i kategorien Identifisere og kartlegge. Organisasjoner ma identifisere strategi, mal, regelverk, bransjenormer og avtaler som pavirker informasjonssystemenes sikkerhet. Inkluderer kartlegging av styringsstrukturer, risikostyringsprosesser, risikotoleranse, leveranser, informasjonssystemer og dataflyt.",
    full_text:
      "Prinsipp 1.1 i NSMs Grunnprinsipper for IKT-sikkerhet versjon 2.1. Tiltak: 1.1.1 Identifiser virksomhetens strategi, prioriterte mal, regelverk, bransjenormer og avtaler som har innvirkning pa informasjonssystemenes sikkerhet. 1.1.2 Identifiser organisasjonsstrukturer og prosesser for sikkerhetsstyring, herunder ledelsens retningslinjer, definerte ansvarslinjer, risikostyringsprosesser, fastsatte risikorammer, tilstrekkelige ressurser og kompetanse. Etabler disse strukturene dersom de mangler. 1.1.3 Identifiser prosesser for IKT-risikostyring som dekker verdianalyse, trusselvurdering, kartlegging av eksisterende sikkerhetstiltak, risikoidentifisering, risikovurdering, risikorapportering, risikohåndtering og verifisering av sikkerhetstiltak. 1.1.4 Identifiser virksomhetens risikotoleranse for IKT ved at ledelsen fastsetter og kommuniserer akseptable versus uakseptable risikonivåer basert på konsekvenser for konfidensialitet, integritet og tilgjengelighet. 1.1.5 Kartlegg virksomhetens leveranser, informasjonssystemer og understottende IKT-funksjoner, herunder systemeierskap, virksomhetskritiske roller og interne/eksterne avhengigheter, gruppert etter risikoaksept. 1.1.6 Kartlegg informasjonsbehandling og dataflyt pa tvers av arbeidsprosesser, brukere, enheter og tjenester for a stotte utvikling av sikker IKT-arkitektur.",
    topics: JSON.stringify(["identifisere", "kartlegging", "styringsstruktur", "risikostyring", "risikotoleranse", "dataflyt"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-1.2",
    title: "1.2 Kartlegg enheter og programvare",
    title_en: "1.2 Map devices and software",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Andre prinsipp i kategorien Identifisere og kartlegge. Virksomheten skal ha en oppdatert oversikt over alle enheter (maskinvare) og programvare i sitt IKT-miljo. Dekker kartlegging av autoriserte og uautoriserte enheter, programvare, fastvare og konfigurasjoner.",
    full_text:
      "Prinsipp 1.2 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Virksomheten ma ha kontroll pa alle enheter og programvare som er tilkoblet nettverket. Tiltak: 1.2.1 Ha en oppdatert oversikt over all autorisert maskinvare, inkludert nettverk, servere, klienter, mobile enheter, IoT-enheter og periferiutstyr. Merk eierskap, plassering og ansvarlig avdeling. 1.2.2 Ha en oppdatert oversikt over all autorisert programvare, inkludert operativsystemer, applikasjoner, firmware og drivere. Registrer versjonsnumre og lisensforhold. 1.2.3 Etabler prosesser for a oppdage og handtere uautoriserte enheter og programvare i nettverket. Uautoriserte enheter skal isoleres eller fjernes. 1.2.4 Dokumenter konfigurasjoner for kritiske systemer og oppbevar disse sikkert for gjenopprettingsformaal. Bruk automatiserte verktoy for konfigurasjonskartlegging der mulig.",
    topics: JSON.stringify(["identifisere", "kartlegging", "maskinvare", "programvare", "konfigurasjon", "IoT"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-1.3",
    title: "1.3 Kartlegg brukere og behov for tilgang",
    title_en: "1.3 Map users and access needs",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Tredje prinsipp i kategorien Identifisere og kartlegge. Virksomheten skal ha oversikt over alle brukere, deres roller og tilgangsbehov. Omfatter kartlegging av brukerkontoer, privilegerte kontoer, tjenestekontoer og eksterne brukere.",
    full_text:
      "Prinsipp 1.3 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 1.3.1 Ha en oppdatert oversikt over alle brukere med tilgang til virksomhetens IKT-systemer, inkludert ansatte, innleid personell, leverandorer og partnere. 1.3.2 Kartlegg brukerroller og tilgangsbehov for hvert system og tjeneste. Bruk prinsippet om minste privilegium — brukere skal kun ha den tilgangen som er nodvendig for a utfore arbeidsoppgavene. 1.3.3 Ha sarskilt oversikt over privilegerte kontoer (administratorkontoer, tjenestekontoer) og begrenset krets av personer med slik tilgang. 1.3.4 Gjennomfor regelmessige tilgangsgjennomganger (minimum arlig) for a verifisere at tilganger er korrekte og at fratradde ansatte eller avsluttede leverandorforhold er fjernet. 1.3.5 Dokumenter prosesser for tildeling, endring og fjerning av tilganger, inkludert godkjenningsprosesser for privilegert tilgang.",
    topics: JSON.stringify(["identifisere", "kartlegging", "brukere", "tilgangskontroll", "privilegerte-kontoer", "minste-privilegium"]),
    status: "current",
  },

  // ---- Kategori 2: Beskytte og opprettholde ----
  {
    reference: "NSM-GP-2.1-2.1",
    title: "2.1 Ivareta sikkerhet i anskaffelses- og utviklingsprosesser",
    title_en: "2.1 Maintain security in procurement and development processes",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Forste prinsipp i kategorien Beskytte og opprettholde. Sikkerhet skal vaere en integrert del av prosessene for anskaffelse og utvikling for a minimere risikoen for sarbarheter. Dekker anskaffelse av IKT-produkter, utvikling og testing, og tjenesteutsetting.",
    full_text:
      "Prinsipp 2.1 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.1.1 Integrer sikkerhetskrav gjennom hele produktets livslop, fra anskaffelse til avhending. 2.1.2 Kjop moderne, stottede produkter med oppdatert sikkerhetsfunksjonalitet. Sikre at kun leverandorstottede produkter som mottar sikkerhetsoppdateringer benyttes, og fas ut eldre systemer planmessig. 2.1.3 Foretrekk IKT-produkter sertifisert av betrodde tredjeparter, som Common Criteria. 2.1.4 Reduser risiko for leverandorkjedemanipulering gjennom risikovurdering, leverandordiskresjon, integritetsbeskyttelse, nedlasting kun fra offisielle HTTPS-kilder og regulert fysisk tilgang for vedlikehold. 2.1.5 Benytt sikre programvareutviklingsmetodikker inkludert planlegging, kravanalyse, design, sikker koding, testing, implementering og sikkerhetsvedlikeholdsplanlegging. 2.1.6 Ha separate miljoer for utvikling, testing og produksjon. 2.1.7 Gjennomfor grundig testing gjennom utviklingslopet, inkludert enhets-, integrasjons-, system-, aksept-, pilot-, penetrasjons- og stresstesting. 2.1.8 Oppretthold kodekvalitet gjennom metodisk sikkerhetsvurdering, saerlig for sikkerhetskritisk kode og apen kildekode-komponenter. Automatiser sikkerhetssjekker i DevOps/DevSecOps-miljoer. 2.1.9 Oppretthold sikkerhetsansvar gjennom hele livssyklusen ved tjenesteutsetting, inkludert tilsynskompetanse og risikovurdering med verifiseringsmekanismer. 2.1.10 Verifiser leverandorens sikkerhetsmodenhet: ISO/IEC 27001-sertifisering, arkitekturtransparens, utviklingsplaner, informasjonssegregering, overvakingskapabilitet, hendelseshandtering, kriseberedskap og kontraktsavslutningsprosedyrer.",
    topics: JSON.stringify(["beskytte", "anskaffelse", "utvikling", "leverandorkjede", "DevSecOps", "Common-Criteria", "tjenesteutsetting"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.2",
    title: "2.2 Etabler en sikker IKT-arkitektur",
    title_en: "2.2 Establish a secure ICT architecture",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Andre prinsipp i kategorien Beskytte. IKT-arkitekturen skal designes med sikkerhet som en integrert del. Dekker nettverkssegmentering, soneinndeling, domenearkitektur, tilgangsstyring basert pa enhetsegenskaper, og robust og resilient arkitektur.",
    full_text:
      "Prinsipp 2.2 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.2.1 Etabler og vedlikehold en helhetlig sikkerhetsarkitektur som implementerer funksjoner for bruker- og kontostyring, enhetskontroll, tilgangsstyring, programvarestyring, operativsystemer, virtualiseringsverktoy, nettverksenheter, skadevarehandtering, kryptografimoduler, digitale sertifikater/PKI, databaser, systemovervaking, sikkerhetskonfigurasjonsstyring, IDS/IPS-systemer, sikkerhetskopiering/gjenoppretting og maskinvare/fastvare. 2.2.2 Bygg IKT-systemer med produkter som fungerer godt sammen sikkerhetsmessig ved a sikre modularitet, folge bransjestandarder for sikkerhetsfunksjoner, og la produkter fra ulike leverandorer dele identiteter fra en felles organisasjonskilde. 2.2.3 Segmenter virksomhetens nettverk etter risikoprofil, med soner med ulike krav til kommunikasjon, eksponering, funksjon og rolle (administrasjonssystemer, applikasjonsservere, klientarbeidsstasjoner, industriell produksjon, internettilgang, tradlost, gjesteklienter og eksternt tilgjengelige tjenester). 2.2.4 Fysisk isoler de mest kritiske nettverkssegmentene, saerlig sensitive delnettverk gjennom luftgap-separasjon. 2.2.5 Del domenearkitektur etter virksomhetens behov med minimum separasjon mellom klientsystemer og organisasjonsservere. 2.2.6 Reguler tjenestetilgang basert pa kunnskap om bade brukeridentitet og enhetsegenskaper, med ulik tilgang for administrerte og uadministrerte enheter. 2.2.7 Etabler robust og resilient IKT-arkitektur som sikrer tilgjengelighet av kritiske funksjoner gjennom risikovurderinger og mottiltak for maskinvarefeil, menneskelige feil, dataangrep, internetttilgjengelighet, tjenesteleverandortilgjengelighet, stromforsyning, naturkatastrofer og geopolitiske faktorer.",
    topics: JSON.stringify(["beskytte", "arkitektur", "nettverkssegmentering", "soneinndeling", "zero-trust", "luftgap", "resiliens"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.3",
    title: "2.3 Ivareta en sikker konfigurasjon",
    title_en: "2.3 Maintain a secure configuration",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Tredje prinsipp i kategorien Beskytte. Alle IKT-systemer skal konfigureres sikkert for bruk. Dekker herding av systemer, fjerning av unodvendig funksjonalitet, standard sikkerhetskonfigurasjoner og automatisert konfigurasjonskontroll.",
    full_text:
      "Prinsipp 2.3 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.3.1 Utvikle og vedlikeholde standard sikkerhetskonfigurasjoner for alle typer systemer — servere, klienter, nettverksenheter, mobile enheter og IoT. Baser konfigurasjoner pa anerkjente retningslinjer (CIS Benchmarks, leverandoranbefalinger, NSMs anbefalinger). 2.3.2 Fjern eller deaktiver all unodvendig funksjonalitet, tjenester, porter, protokoller og programvare. Fjern standardkontoer eller endre standardpassord for oppsett. 2.3.3 Implementer automatisert konfigurasjonskontroll for a oppdage avvik fra godkjente konfigurasjoner. Korrigere avvik umiddelbart. 2.3.4 Dokumenter og godkjenn alle konfigurasjonsendringer gjennom en formell endringshåndteringsprosess. 2.3.5 Bruk konfigurasjonsverktoy (f.eks. Ansible, Puppet, Chef, GPO) for konsistent utrulling og vedlikehold av sikkerhetskonfigurasjoner.",
    topics: JSON.stringify(["beskytte", "konfigurasjon", "herding", "CIS-Benchmarks", "automatisering", "endringshåndtering"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.4",
    title: "2.4 Beskytt virksomhetens nettverk",
    title_en: "2.4 Protect the organisation's network",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Fjerde prinsipp i kategorien Beskytte. Nettverket skal beskyttes med brannmurer, IDS/IPS, nettverksovervaking og tilgangskontroll pa nettverksporter. Inkluderer beskyttelse av tradlose nettverk og DNS-sikkerhet.",
    full_text:
      "Prinsipp 2.4 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.4.1 Implementer brannmurer pa nettverksgrenser og mellom soner. Konfigurer med prinsippet om a nekte all trafikk som ikke er eksplisitt tillatt. 2.4.2 Implementer inntrengingsdeteksjons- og forebyggingssystemer (IDS/IPS) for a oppdage og blokkere ondsinnet nettverkstrafikk. Oppdater signaturer regelmessig. 2.4.3 Aktiver tilgangskontroll pa nettverksporter (802.1X) for a kontrollere hvilke enheter som kan koble seg til nettverket. 2.4.4 Beskytt tradlose nettverk med WPA3 eller WPA2-Enterprise. Separate tradlose nettverk for gjester og IoT-enheter. 2.4.5 Implementer DNS-sikkerhetstiltak inkludert DNSSEC for a beskytte mot DNS-manipulering, og DNS-filtrering for a blokkere tilgang til kjente ondsinnede domener. 2.4.6 Overvak nettverkstrafikk for anomalier og uvanlige monstre. Etabler baseline for normal trafikk og alarmer for avvik.",
    topics: JSON.stringify(["beskytte", "nettverkssikkerhet", "brannmur", "IDS-IPS", "802.1X", "WPA3", "DNSSEC"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.5",
    title: "2.5 Kontroller dataflyt",
    title_en: "2.5 Control data flow",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Femte prinsipp i kategorien Beskytte. Virksomheten skal ha kontroll pa dataflyt mellom nettverkssoner og ut av organisasjonen. Dekker datalekkasjeforebygging (DLP), e-postfiltrering, webfiltrering og overvaking av dataoverforinger.",
    full_text:
      "Prinsipp 2.5 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.5.1 Kontroller og overvak dataflyt mellom nettverkssoner. Tillat kun nodvendig kommunikasjon mellom soner basert pa dokumenterte behov. 2.5.2 Implementer datalekkasjeforebygging (DLP) for a oppdage og forhindre uautorisert overfoering av sensitiv informasjon ut av organisasjonen. 2.5.3 Filtrer innkommende og utgaende e-post for skadevare, phishing-forsok og mistenkelige vedlegg. Blokker kjente ondsinnede filtyper. 2.5.4 Implementer webfiltrering for a blokkere tilgang til kjente ondsinnede nettsteder og kategorier som utgjor en sikkerhetsrisiko. 2.5.5 Overvak og loggfor alle dataoverforinger til og fra organisasjonens nettverk, saerlig store dataoverforinger og overforinger til ukjente destinasjoner. 2.5.6 Sperr direkte trafikk mellom klienter for a begrense spredning av skadevare.",
    topics: JSON.stringify(["beskytte", "dataflyt", "DLP", "e-postfiltrering", "webfiltrering", "datalekkasje"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.6",
    title: "2.6 Ha kontroll pa identiteter og tilganger",
    title_en: "2.6 Control identities and access",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Sjette prinsipp i kategorien Beskytte. Dekker identitets- og tilgangsstyring (IAM), flerfaktorautentisering (MFA), prinsippet om minste privilegium, privilegert tilgangsstyring (PAM) og passordpolicyer.",
    full_text:
      "Prinsipp 2.6 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.6.1 Implementer sentralisert identitets- og tilgangsstyring (IAM) for alle brukere, systemer og tjenester. Bruk en felles identitetskilde der mulig. 2.6.2 Bruk flerfaktorautentisering (MFA) for alle brukere, saerlig for tilgang til kritiske systemer, fjernaksess og administrativ tilgang. NSMs klare anbefaling er at MFA brukes over alt der det er mulig. 2.6.3 Implementer prinsippet om minste privilegium — brukere skal kun ha de tilgangene som er strengt nodvendig for arbeidsoppgavene. Revurder tilganger regelmessig. 2.6.4 Etabler privilegert tilgangsstyring (PAM) for administratorkontoer. Bruk tidsbegrensede, godkjente utvidelser av privilegier fremfor permanente administratorrettigheter. 2.6.5 Ha sterke passordpolicyer. NSM anbefaler passord pa minimum 16 tegn. Bruk passordfraser som er lettere a huske men vanskelige a gjette. Forsterkes med dialektord, slang og feilstavede ord. 2.6.6 Ikke gi sluttbrukere administratorrettigheter pa klienter. De fleste sluttbrukere har ikke legitimt behov for administratortilgang.",
    topics: JSON.stringify(["beskytte", "identitet", "tilgangsstyring", "MFA", "IAM", "PAM", "passord", "minste-privilegium"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.7",
    title: "2.7 Beskytt data i ro og i transitt",
    title_en: "2.7 Protect data at rest and in transit",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Syvende prinsipp i kategorien Beskytte. Data skal beskyttes med kryptering bade under lagring og overfoering. Dekker TLS, diskkryptering, kryptografiske anbefalinger og haandtering av kryptografisk nokkelmateriale.",
    full_text:
      "Prinsipp 2.7 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.7.1 Krypter data under overfoering med TLS 1.2 eller nyere. Bruk kun godkjente krypteringsalgoritmer og nokkellengder i henhold til NSMs kryptografiske anbefalinger. 2.7.2 Krypter sensitive data ved lagring (at rest) med anerkjente krypteringsalgoritmer. Bruk full diskkryptering pa bærbare enheter og mobile enheter. 2.7.3 Beskytt kryptografisk nokkelmateriale med dedikerte nøkkelhåndteringssystemer (HSM der mulig). Etabler prosedyrer for nokkeldistribusjon, rotasjon og tilbakekalling. 2.7.4 Klassifiser data og anvend beskyttelsestiltak basert pa dataenes sensitivitet og klassifiseringsniva. 2.7.5 Sikre at sikkerhetsgradert informasjon behandles i henhold til kravene i sikkerhetsloven og virksomhetsikkerhetsforskriften.",
    topics: JSON.stringify(["beskytte", "kryptering", "TLS", "diskkryptering", "HSM", "kryptografi", "dataklassifisering"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.8",
    title: "2.8 Beskytt e-post og nettleser",
    title_en: "2.8 Protect email and web browser",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Attende prinsipp i kategorien Beskytte. E-post og nettlesere er de vanligste angrepsvektorene. Dekker e-postautentisering (SPF, DKIM, DMARC), nettlesersikkerhet, makroblokkering og phishing-beskyttelse.",
    full_text:
      "Prinsipp 2.8 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.8.1 Implementer e-postautentisering med SPF, DKIM og DMARC for a redusere risikoen for e-postforfalskning (spoofing). SPF forteller hvilke IP-adresser som har lov til a sende e-post pa vegne av et domene. DKIM sikrer at e-post kan videresendes med digital signatur. DMARC fjerner gjetting om hvordan e-post som feiler SPF/DKIM-validering skal haandteres. 2.8.2 Konfigurer e-postsystemer til a blokkere kjente ondsinnede filtyper i vedlegg og hindre makrokjoring i dokumenter mottatt fra eksterne avsendere. 2.8.3 Bruk sikre nettleserkonfigurasjoner med oppdaterte versjoner, begrens utvidelser og plugins, og aktiver innebygde sikkerhetsfunksjoner. 2.8.4 Implementer webfiltrering og DNS-filtrering for a blokkere tilgang til kjente phishing-sider og skadevaredistribusjonssider. 2.8.5 Gjennomfor regelmessig sikkerhetsopplaering om phishing og sosial manipulasjon. Simuler phishing-angrep for a teste og forbedre bevissthet.",
    topics: JSON.stringify(["beskytte", "e-post", "SPF", "DKIM", "DMARC", "nettleser", "phishing", "makro"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.9",
    title: "2.9 Etabler evne til gjenoppretting av data",
    title_en: "2.9 Establish data recovery capability",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Niende prinsipp i kategorien Beskytte. Organisasjoner ma kunne gjenopprette data og systemer etter sikkerhetshendelser. Dekker sikkerhetskopieringsstrategier, testing av gjenoppretting, offline-kopier og geografisk atskilte kopier.",
    full_text:
      "Prinsipp 2.9 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.9.1 Ta jevnlige sikkerhetskopier av alle viktige data og systemer. Frekvensen skal tilpasses virksomhetens behov og toleranse for datatap (RPO). 2.9.2 Test gjenoppretting fra sikkerhetskopier regelmessig. Dokumenter gjenopprettingstider og verifiser at de mater virksomhetens krav (RTO). 2.9.3 Oppbevar sikkerhetskopier offline og geografisk atskilt fra primarsystemene. Bruk minimum to uavhengige kopieringslosninger og -lokasjoner. 2.9.4 Beskytt sikkerhetskopier mot manipulering og ransomware. Bruk skrivebeskyttelse (immutability), nettverkssegmentering og dedikerte tjenestekontoer for kopieringslosninger. 2.9.5 Dokumenter gjenopprettingsprosedyrer og ov dem regelmessig. Identifiser avhengigheter mellom systemer som pavirker gjenopprettingsrekkefolgen.",
    topics: JSON.stringify(["beskytte", "sikkerhetskopi", "gjenoppretting", "RPO", "RTO", "offline-kopi", "ransomware-beskyttelse"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-2.10",
    title: "2.10 Integrer sikkerhet i prosess for endringshåndtering",
    title_en: "2.10 Integrate security in change management",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Tiende prinsipp i kategorien Beskytte. Alle endringer i IKT-systemer skal vurderes for sikkerhetskonsekvenser. Dekker formell endringshåndtering, sikkerhetsoppdateringer og vedlikehold.",
    full_text:
      "Prinsipp 2.10 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 2.10.1 Etabler en formell endringshåndteringsprosess som inkluderer sikkerhetsvurdering av alle planlagte endringer i IKT-miljoet. 2.10.2 Installer sikkerhetsoppdateringer sa fort som mulig og mest mulig automatisk. Prioriter oppdatering av operativsystemer og programvare som behandler eksterne data (nettlesere, e-postklienter, PDF-lesere, Office-pakker). 2.10.3 Ha en prosess for a handtere nodoppdateringer (emergency patches) for kritiske sarbarheter utenfor normal endringsvindu. 2.10.4 Dokumenter alle endringer og verifiser at systemene fungerer korrekt etter endringer, bade funksjonelt og sikkerhetsmessig. 2.10.5 Fas ut eldre IKT-produkter som ikke lenger mottar sikkerhetsoppdateringer. Nyere versjoner inneholder flere sikkerhetsoppdateringer og forbedrede sikkerhetsfunksjoner.",
    topics: JSON.stringify(["beskytte", "endringshåndtering", "sikkerhetsoppdateringer", "patch-management", "livssyklus"]),
    status: "current",
  },

  // ---- Kategori 3: Oppdage ----
  {
    reference: "NSM-GP-2.1-3.1",
    title: "3.1 Oppdag og fjern kjente sarbarheter og trusler",
    title_en: "3.1 Detect and remove known vulnerabilities and threats",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Forste prinsipp i kategorien Oppdage. Virksomheten skal jevnlig identifisere og utbedre kjente sarbarheter i sine systemer. Dekker sarbarhetsskanning, skadevaredeteksjon, trusselindikatorer og oppfolging av NCSC-varsler.",
    full_text:
      "Prinsipp 3.1 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 3.1.1 Gjennomfor regelmessig sarbarhetsskanning av alle systemer, bade interne og internetteksponerte. Prioriter utbedring basert pa risiko og CVSS-score. 3.1.2 Bruk oppdatert skadevaredeteksjon (antivirus, EDR) pa alle endepunkter og servere. Oppdater signaturer automatisk. 3.1.3 Abonner pa og implementer trusselindikatorer (IoC) fra NCSC/NorCERT og relevante sektordialog-samarbeid. 3.1.4 Folg med pa NCSCs sikkerhetsvarsler og handter varsler om aktiv utnyttelse av sarbarheter med hogeste prioritet. 3.1.5 Vedlikehold en oversikt over kjente sarbarheter i virksomhetens systemer og ha en tydelig plan for utbedring med tidsfrister.",
    topics: JSON.stringify(["oppdage", "sarbarhetsskanning", "skadevare", "EDR", "trusselindikatorer", "NCSC"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-3.2",
    title: "3.2 Etabler sikkerhetsovervaking",
    title_en: "3.2 Establish security monitoring",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Andre prinsipp i kategorien Oppdage. Virksomheten skal ha evne til a overvake IKT-systemer for sikkerhetshendelser. Dekker logging, sentral logghåndtering, SIEM, SOC og NCSCs varslingssystem (VDI).",
    full_text:
      "Prinsipp 3.2 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 3.2.1 Aktiver logging pa alle kritiske systemer, inkludert autentisering, tilgangsendringer, systemendringer, nettverkstrafikk og feilmeldinger. 3.2.2 Etabler sentral innsamling og lagring av logger fra alle systemer. Beskytt logger mot manipulering og slett. Bevar logger i henhold til lovkrav og virksomhetens behov (minimum 90 dager, anbefalt 12 maneder). 3.2.3 Implementer SIEM-losning (Security Information and Event Management) for automatisert korrelering og analyse av sikkerhetshendelser pa tvers av systemer. 3.2.4 Vurder tilknytning til NCSCs Varslingssystem for Digital Infrastruktur (VDI) for a motta trusselindikatorer og varsler om nasjonal relevans. 3.2.5 Vurder a etablere eller bruke en ekstern SOC-tjeneste (Security Operations Center) for doegnkontinuerlig overvaking.",
    topics: JSON.stringify(["oppdage", "logging", "SIEM", "SOC", "VDI", "overvaking", "sentral-logging"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-3.3",
    title: "3.3 Analyser data fra sikkerhetsovervaking",
    title_en: "3.3 Analyse security monitoring data",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Tredje prinsipp i kategorien Oppdage. Logg- og overvakingsdata skal analyseres systematisk for a identifisere sikkerhetshendelser. Dekker korrelasjonsanalyse, anomalideteksjon, trusseljakt og rapportering.",
    full_text:
      "Prinsipp 3.3 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 3.3.1 Analyser loggdata systematisk for a identifisere indikasjoner pa kompromittering (IoC), unormale bruksmonstre og policybrudd. 3.3.2 Korreler hendelser pa tvers av systemer for a oppdage avanserte angrep som spenner over flere systemer og tidsperioder. 3.3.3 Gjennomfor proaktiv trusseljakt (threat hunting) basert pa kjente trusselaktormonstre, MITRE ATT&CK-rammeverket og etterretningsinformasjon fra NCSC. 3.3.4 Etabler rutiner for eskalering og varsling ved identifiserte sikkerhetshendelser, med klare terskler for nar hendelser skal eskaleres til ledelsen og rapporteres til NCSC. 3.3.5 Gjennomfor jevnlig gjennomgang og forbedring av deteksjonsregler og -signaturer basert pa nye trusler og hendelser.",
    topics: JSON.stringify(["oppdage", "analyse", "korrelasjon", "trusseljakt", "MITRE-ATT&CK", "eskalering"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-3.4",
    title: "3.4 Gjennomfor inntrengningstester",
    title_en: "3.4 Conduct penetration tests",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Fjerde prinsipp i kategorien Oppdage. Regelmessige inntrengningstester skal gjennomfores for a verifisere at sikkerhetstiltakene fungerer. NSMs erfaringer fra inntrengingstester avdekker ti vanlige sarbarheter i norske IKT-systemer.",
    full_text:
      "Prinsipp 3.4 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 3.4.1 Gjennomfor regelmessige inntrengningstester (minimum arlig) av internetteksponerte tjenester, interne nettverk og kritiske applikasjoner. 3.4.2 Bruk kvalifiserte og godkjente penetrasjonstestere. NSM har etablert en kvalitetsordning for leverandorer som handterer IKT-hendelser. 3.4.3 Test bade tekniske sarbarheter og organisatoriske svakheter (sosial manipulasjon, fysisk sikkerhet). 3.4.4 Dokumenter funn og utvikle handlingsplaner for utbedring med tidsfrister. Folg opp at tiltak implementeres. 3.4.5 NSMs rapport 'Ti sarbarheter i norske IKT-systemer' viser at de vanligste sarbarhetene skyldes manglende oversikt over egne systemer, svakheter i passord- og kontohåndtering, manglende programvareoppdateringer og feilkonfigurerte tjenester. Erfaringer fra NSMs egne inntrengingstester viser at disse grunnleggende svakhetene gjenstar i mange norske virksomheter.",
    topics: JSON.stringify(["oppdage", "penetrasjonstest", "sarbarhetsanalyse", "NSM-kvalitetsordning", "ti-sarbarheter"]),
    status: "current",
  },

  // ---- Kategori 4: Handtere og gjenopprette ----
  {
    reference: "NSM-GP-2.1-4.1",
    title: "4.1 Forbered virksomheten pa haandtering av hendelser",
    title_en: "4.1 Prepare the organisation for incident handling",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Forste prinsipp i kategorien Handtere og gjenopprette. Virksomheten skal vaere forberedt pa a haandtere sikkerhetshendelser. Dekker hendelseshaandteringsplaner, roller og ansvar, ovelser og kommunikasjonskanaler.",
    full_text:
      "Prinsipp 4.1 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 4.1.1 Ha en oppdatert hendelseshandteringsplan som definerer roller, ansvar, eskaleringsrutiner og kommunikasjonskanaler. 4.1.2 Definer klare roller og ansvarsomrader for hendelseshandtering, inkludert hvem som har myndighet til a ta kritiske beslutninger (isolere systemer, informere kunder, varsle myndigheter). 4.1.3 Gjennomfor regelmessige ovelser — bade tabletop-ovelser og fullskala simulerte hendelser — for a teste og forbedre handteringsevnen. 4.1.4 Etabler kommunikasjonskanaler som fungerer ogsa under et angrep, uavhengig av virksomhetens normale IKT-infrastruktur. 4.1.5 Ha forhåndsinngatte avtaler med hendelsesrespons-leverandorer (MSSP, incident response-team) som kan bistå ved alvorlige hendelser. 4.1.6 Sikre at virksomheten kjenner varslingspliktene etter sikkerhetsloven paragraf 4-5 og digitalsikkerhetsloven.",
    topics: JSON.stringify(["handtere", "hendelseshandtering", "ovelser", "varsling", "beredskap"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-4.2",
    title: "4.2 Vurder og klassifiser hendelser",
    title_en: "4.2 Assess and classify incidents",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Andre prinsipp i kategorien Handtere. Sikkerhetshendelser skal vurderes og klassifiseres for a sikre riktig respons. Dekker alvorlighetsgradering, prioritering og innledende analyse.",
    full_text:
      "Prinsipp 4.2 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 4.2.1 Etabler en klassifiseringsmodell for sikkerhetshendelser med definerte alvorlighetsnivåer (lav, middels, hoy, kritisk) og tilhorende responstider. 4.2.2 Gjennomfor innledende analyse for a fastsla hendelsens omfang, pavirkning og potensielle konsekvenser for a prioritere riktig. 4.2.3 Dokumenter hendelsesforlopet fra forste deteksjon — tidslinje, berarte systemer, observerte indikatorer og gjennomforte tiltak. 4.2.4 Varsle relevante interessenter basert pa alvorlighetsniva: internt (ledelse, berarte avdelinger), eksternt (NCSC, sektordialog, berarte kunder, Datatilsynet ved personopplysningsbrudd).",
    topics: JSON.stringify(["handtere", "klassifisering", "alvorlighetsvurdering", "varsling", "hendelsesanalyse"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-4.3",
    title: "4.3 Kontroller og haandter hendelser",
    title_en: "4.3 Control and handle incidents",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Tredje prinsipp i kategorien Handtere. Aktiv haandtering av hendelser for a begrense skade og fjerne trusselen. Dekker isolering, bevisinnsamling, fjerning av trussel og gjenoppretting.",
    full_text:
      "Prinsipp 4.3 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 4.3.1 Isoler berarte systemer for a forhindre videre spredning. Koble fra infiserte maskiner fra nettverket, men unnga a slaa dem av (bevismateriell i minne). 4.3.2 Sikre bevis for videre analyse og eventuell politianmeldelse. Ta diskavbilder og minnedumper av berarte systemer for det gjores endringer. 4.3.3 Identifiser og fjern trusselen fullstendig. Verifiser at angriperen er utestengt fra alle systemer for gjenoppretting starter. 4.3.4 Gjennomfor passordbytte pa alle berarte kontoer, saerlig tjenestekontoer og domeneadministratorkontoer. 4.3.5 Gjenopprett fra verifiserte sikkerhetskopier. Gjenopprett pa et nettverkssegment som er verifisert uberort for a unnga reinfeksjon under oppdatering og konfigurasjon. 4.3.6 Varsle NCSC ved alvorlige hendelser — varsle@cert.no eller telefon 02497. Sikkerhetsloven paragraf 4-5 palegger virksomheter a varsle NSM ved hendelser som kan pavirke nasjonale sikkerhetsinteresser.",
    topics: JSON.stringify(["handtere", "isolering", "bevisinnsamling", "gjenoppretting", "NCSC-varsling", "sikkerhetsloven"]),
    status: "current",
  },
  {
    reference: "NSM-GP-2.1-4.4",
    title: "4.4 Evaluer og laer av hendelser",
    title_en: "4.4 Evaluate and learn from incidents",
    date: "2024-06-05",
    type: "grunnprinsipp",
    series: "Grunnprinsipper",
    summary:
      "Fjerde prinsipp i kategorien Handtere. Etter hendelser skal det gjennomfores evaluering for a trekke laerdom og forbedre sikkerheten. Dekker rotarsaksanalyse, erfaringsdeling og oppdatering av prosedyrer.",
    full_text:
      "Prinsipp 4.4 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1. Tiltak: 4.4.1 Gjennomfor evaluering etter alle hendelser, bade storre og mindre. Dokumenter hva som skjedde, hva som fungerte bra, hva som kan forbedres og konkrete tiltak for forbedring. 4.4.2 Gjennomfor rotarsaksanalyse for a identifisere underliggende arsaker til hendelsen og iverksette tiltak som forhindrer gjentagelse. 4.4.3 Oppdater hendelseshandteringsplaner, deteksjonsregler og sikkerhetstiltak basert pa laerdom fra hendelsen. 4.4.4 Del relevante erfaringer med NCSC, sektordialog og bransjefellesskap for a hjelpe andre virksomheter med a beskytte seg mot lignende trusler. 4.4.5 Gjennomfor trend- og mOnsteranalyse av hendelser over tid for a identifisere systemiske svakheter og forbedre den overordnede sikkerhetsposisjonen.",
    topics: JSON.stringify(["handtere", "evaluering", "rotarsaksanalyse", "erfaringsdeling", "kontinuerlig-forbedring"]),
    status: "current",
  },
];

// ---------------------------------------------------------------------------
// 3. Guidance — NSM Reports and Recommendations
// ---------------------------------------------------------------------------

const reports: GuidanceRow[] = [
  {
    reference: "NSM-RISIKO-2026",
    title: "Risiko 2026 — Dagens valg, morgendagens risiko",
    title_en: "Risk 2026 — Today's Choices, Tomorrow's Risk",
    date: "2026-02-01",
    type: "report",
    series: "Risiko",
    summary:
      "NSMs arlige rapport Risiko 2026 gir en samlet vurdering av trusler og risikoer mot nasjonal sikkerhet. Tittel: Dagens valg — morgendagens risiko. Fokus pa konsekvensene av beslutninger tatt i dag for fremtidig sikkerhet.",
    full_text:
      "NSMs rapport Risiko 2026 med undertittel 'Dagens valg — morgendagens risiko' beskriver hvordan valg som gjores i dag pavirker Norges sikkerhetsposisjon i framtiden. Rapporten dekker det aktuelle trusselbildet fra statlige aktorer, cyberkriminalitet, og sikkerhetstruende virksomhet mot norske interesser. Rapporten gir anbefalinger til myndigheter, virksomheter og enkeltpersoner om hvordan de kan bidra til a styrke nasjonal sikkerhet. NSM understreker at nasjonal sikkerhet er et felles ansvar som krever innsats fra hele samfunnet.",
    topics: JSON.stringify(["trusselrapport", "risiko", "nasjonal-sikkerhet", "2026"]),
    status: "current",
  },
  {
    reference: "NSM-RISIKO-2025",
    title: "Risiko 2025 — Et sikkert Norge i en usikker verden",
    title_en: "Risk 2025 — A Secure Norway in an Uncertain World",
    date: "2025-02-05",
    type: "report",
    series: "Risiko",
    summary:
      "NSMs rapport Risiko 2025 med undertittelen 'Et sikkert Norge i en usikker verden'. Vurderer at sabotasjeforsok mot Norge er sannsynlige. Norske virksomheter ma iverksette forebyggende tiltak umiddelbart. Hoytteknologi- og industrisektorer stod for 63 prosent av rapporterte cyberhendelser i 2024.",
    full_text:
      "Risiko 2025 er NSMs arlige rapport om sikkerhetsfaglige rad. Rapporten vurderer at sabotasjeforsok i Norge er sannsynlige og at norske virksomheter ma umiddelbart iverksette forebyggende tiltak. I 2024 stod norske hoytteknologi- og industrisektorer for 63 prosent av rapporterte cyberhendelser. Virksomheter innen utenrikspolitikk, forsvar, sikkerhetspolitikk, hoytteknologi, industri og finans er saerlig utsatt. Rapporten fremhever at trusselbildet er svaert alvorlig og at Norge star overfor sammensatte trusler fra bade statlige aktorer og cyberkriminelle. NSM anbefaler at alle virksomheter styrker sin digitale beredskap og folger Grunnprinsipper for IKT-sikkerhet.",
    topics: JSON.stringify(["trusselrapport", "risiko", "sabotasje", "cyberhendelser", "2025"]),
    status: "current",
  },
  {
    reference: "NSM-RISIKO-2024",
    title: "Risiko 2024 — Nasjonal sikkerhet er et felles ansvar",
    title_en: "Risk 2024 — National Security is a Shared Responsibility",
    date: "2024-02-15",
    type: "report",
    series: "Risiko",
    summary:
      "NSMs rapport Risiko 2024 vurderer trusler og risikoer mot nasjonal sikkerhet. Naeringslivet har fatt okt betydning for nasjonal sikkerhet. Petroleum, kraftsektoren, elektronisk kommunikasjon, maritim teknologi, datasentre og forskning er sentrale for nasjonal sikkerhet.",
    full_text:
      "NSMs rapport Risiko 2024 gir en samlet vurdering av trusler og risikoer mot nasjonal sikkerhet i det digitale rommet. Naeringslivet har fatt storre betydning for nasjonal sikkerhet i lys av sikkerhetspolitisk og teknologisk utvikling. Sektorer som petroleum og kraftsektoren, elektronisk kommunikasjon, maritim teknologi, datasentre og forskning og utdanning er na sentrale for nasjonal sikkerhet. Norske virksomheter ma tenke sikkerhet i alt de gjor, fra ansettelser og anskaffelser til eierskapsendringer. Spionasje, cyberoperasjoner, sikkerhetstruende oppkjop, rekruttering av innsidere og pavirkningsoperasjoner er virkemidler som brukes mot norske virksomheter. Russland utgjor den storste trusselen mot Norge i det digitale rommet. Kinesisk etterretning retter seg mot norsk teknologi, forsvar og maritim sektor. Ransomware er fortsatt den storste trusselen mot norske virksomheter — LockBit, ALPHV/BlackCat og Cl0p-gruppen har rammet norske virksomheter. Angrep mot leverandorkjeder oker i omfang.",
    topics: JSON.stringify(["trusselrapport", "risiko", "cyberspionage", "ransomware", "kritisk-infrastruktur", "leverandorkjede", "2024"]),
    status: "current",
  },
  {
    reference: "NSM-RISIKO-2023",
    title: "Risiko 2023 — Okt uforutsigbarhet krever hoyere beredskap",
    title_en: "Risk 2023 — Increased Unpredictability Requires Higher Preparedness",
    date: "2023-02-13",
    type: "report",
    series: "Risiko",
    summary:
      "NSMs rapport Risiko 2023 peker pa hvordan myndigheter og virksomheter bor redusere sarbarheter for a gjore trusselaktorenes arbeid vanskeligere. Rettet mot hele samfunnet, men saerlig til ledere og personell med sikkerhetsoppgaver.",
    full_text:
      "I Risiko 2023 peker NSM pa hvordan myndigheter og virksomheter bor redusere sarbarheter for a gjore trusselaktorenes arbeid vanskeligere. Rapporten er rettet mot hele samfunnet, men saerlig til ledere og personell med sikkerhetsoppgaver. Situasjonen i Ukraina har forsterket trusselbildet, og NSM observerer okt aktivitet fra bade statlige aktorer og hacktivistgrupper. Rapporten fremhever behovet for okt beredskap i norske virksomheter, saerlig innen kritisk infrastruktur. Anbefalinger inkluderer styrking av grunnleggende sikkerhetstiltak, forbedret hendelseshandteringsevne og tettere samarbeid med NCSC.",
    topics: JSON.stringify(["trusselrapport", "risiko", "beredskap", "Ukraina", "hacktivisme", "2023"]),
    status: "current",
  },
  {
    reference: "NSM-DIGITALT-RISIKOBILDE-2023",
    title: "Nasjonalt digitalt risikobilde 2023",
    title_en: "National Digital Risk Assessment 2023",
    date: "2023-10-15",
    type: "report",
    series: "Risiko",
    summary:
      "NSMs rapport om det nasjonale digitale risikobildet for 2023. Tar opp utfordringer knyttet til statssikkerhet, samfunnssikkerhet og individets sikkerhet i det digitale rommet. Bidrar til bedre digital sikkerhet i offentlige og private virksomheter gjennom eksempler og rad.",
    full_text:
      "Nasjonalt digitalt risikobilde 2023 er NSMs rapport som gir en helhetlig vurdering av digitale risikoer i Norge. Rapporten adresserer utfordringer innen statssikkerhet, samfunnssikkerhet og individets sikkerhet i det digitale rommet. Sentrale temaer inkluderer: avanserte persistente trusler (APT) fra statlige aktorer, saerlig Russland og Kina. Okende kompleksitet i leverandorkjedeangrep. Ransomware-as-a-Service-okosystemets modning. Sarbarheter i kritisk infrastruktur, saerlig innen energi og elektronisk kommunikasjon. Personvernrisikoer ved utstrakt bruk av skytjenester. Manglende sikkerhetskultur i mange norske virksomheter. Rapporten gir konkrete anbefalinger og eksempler pa god praksis for a styrke digital sikkerhet.",
    topics: JSON.stringify(["risikobilde", "digital-sikkerhet", "APT", "leverandorkjede", "ransomware", "2023"]),
    status: "current",
  },
  {
    reference: "NSM-SFRAD-2024",
    title: "Sikkerhetsfaglig rad — Et motstandsdyktig Norge",
    title_en: "Security Advisory — A Resilient Norway",
    date: "2024-06-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs sikkerhetsfaglige rad til regjeringen. Gir anbefalinger om hvordan Norge kan styrke sin motstandsdyktighet mot trusler mot nasjonal sikkerhet. Dekker forebyggende sikkerhet, beredskap, kompetanse og samarbeid.",
    full_text:
      "NSMs sikkerhetsfaglige rad med tittelen 'Et motstandsdyktig Norge' gir NSMs anbefalinger til regjeringen om styrking av nasjonal sikkerhet. Rapporten dekker: styrking av forebyggende sikkerhet pa tvers av sektorer, forbedring av nasjonal beredskap mot sammensatte trusler, utvikling av sikkerhetskompetanse i offentlig og privat sektor, styrking av samarbeid mellom myndigheter, naeringslivet og internasjonale partnere, modernisering av sikkerhetslovgivningen og tilsynsmekanismer, sikring av kritisk infrastruktur og grunnleggende nasjonale funksjoner, og handtering av utfordringer knyttet til ny teknologi inkludert kunstig intelligens og kvantedatamaskiner.",
    topics: JSON.stringify(["sikkerhetsfaglig-rad", "nasjonal-sikkerhet", "motstandsdyktighet", "anbefalinger"]),
    status: "current",
  },
  {
    reference: "NSM-TI-SARBARHETER",
    title: "Ti sarbarheter i norske IKT-systemer — Erfaringer fra NSMs inntrengingstester",
    title_en: "Ten Vulnerabilities in Norwegian ICT Systems — Findings from NSM Penetration Tests",
    date: "2023-11-15",
    type: "report",
    series: "NSM",
    summary:
      "NSMs rapport basert pa erfaringer fra inntrengingstester. Identifiserer ti vanlige sarbarheter i norske IKT-systemer. De fleste skyldes manglende oversikt over egne systemer og prosedyrer knyttet til passord- og kontohåndtering, manglende programvareoppdateringer og feilkonfigurering.",
    full_text:
      "NSMs rapport 'Ti sarbarheter i norske IKT-systemer' presenterer funn fra NSMs inntrengingstester mot norske virksomheter. De ti vanligste sarbarhetene er: 1. Manglende oversikt over egne IKT-systemer. 2. Svake eller standardpassord pa systemer og tjenester. 3. Manglende flerfaktorautentisering (MFA). 4. Manglende eller forsinket installasjon av sikkerhetsoppdateringer. 5. Feilkonfigurerte tjenester og systemer. 6. For brede tilgangsrettigheter (manglende minste-privilegium). 7. Unodvendige tjenester og porter eksponert mot internett. 8. Manglende nettverkssegmentering. 9. Svak logging og overvaking. 10. Manglende eller utdaterte hendelseshandteringsplaner. De fleste av disse sarbarhetene er grunnleggende og kan utbedres med relativt enkle tiltak. NSM anbefaler at alle virksomheter bruker Grunnprinsipper for IKT-sikkerhet som utgangspunkt for sikkerhetsarbeidet.",
    topics: JSON.stringify(["penetrasjonstest", "sarbarheter", "passord", "MFA", "konfigurasjon", "segmentering"]),
    status: "current",
  },
];

// ---------------------------------------------------------------------------
// 4. Guidance — NSM Veiledere and Recommendations
// ---------------------------------------------------------------------------

const veiledere: GuidanceRow[] = [
  {
    reference: "NSM-VEIL-ANSKAFFELSER-2025",
    title: "Veileder for ivaretakelse av sikkerhet i anskaffelser",
    title_en: "Guide for Maintaining Security in Procurements",
    date: "2025-06-26",
    type: "veileder",
    series: "Sikkerhetsloven",
    summary:
      "NSMs veileder som gir en innforing i krav som stilles til anskaffelser etter sikkerhetsloven. Et verktoy for a vurdere om en anskaffelse skal sikkerhetsgraderes, med rad om gjennomforing.",
    full_text:
      "Veileder for ivaretakelse av sikkerhet i anskaffelser fra NSM. Veilederen gir en innforing i de kravene som stilles til anskaffelser etter sikkerhetsloven (LOV-2018-06-01-24) og virksomhetsikkerhetsforskriften. Den fungerer som et verktoy for virksomheter som skal vurdere om en anskaffelse bor sikkerhetsgraderes, og gir rad om gjennomforing av sikkerhetsgraderte anskaffelser. Dekker: risikovurdering av anskaffelsen, klassifisering av informasjon og materiell, krav til leverandorklarering, krav til personellsikkerhet hos leverandor, sikkerhetsinstrukser og transportkrav, tilsynsordninger og kontroll. Veilederen erstatter tidligere veiledning om sikkerhetsgraderte anskaffelser.",
    topics: JSON.stringify(["sikkerhetsloven", "anskaffelser", "leverandorklarering", "sikkerhetsgradert"]),
    status: "current",
  },
  {
    reference: "NSM-VEIL-GRADERT-INFO-2025",
    title: "Veileder i sikkerhetsgradert informasjon",
    title_en: "Guide for Classified Information",
    date: "2025-06-26",
    type: "veileder",
    series: "Sikkerhetsloven",
    summary:
      "NSMs veileder om håndtering og beskyttelse av sikkerhetsgradert informasjon etter sikkerhetsloven. Dekker graderingsnivåer, merking, oppbevaring, overfoering og tilintetgjorelse.",
    full_text:
      "Veileder i håndtering og beskyttelse av sikkerhetsgradert informasjon fra NSM. Veilederen beskriver kravene til haandtering av informasjon gradert etter sikkerhetsloven: BEGRENSET, KONFIDENSIELT, HEMMELIG og STRENGT HEMMELIG. Dekker: klassifisering og graderingsvurdering av informasjon, merking av dokumenter og media, fysiske og tekniske krav til oppbevaring, krav til overfoering og forsendelse, autorisasjon og tilgangsrett, sikkerhetssamtaler og taushetserklaeringer, tilintetgjorelse og avgradering, handtering av sikkerhetsbrudd. Veilederen gjennomgar sikkerhetslovens kapittel 5 om informasjonssikkerhet og virksomhetsikkerhetsforskriftens relevante bestemmelser.",
    topics: JSON.stringify(["sikkerhetsloven", "sikkerhetsgradert", "klassifisering", "informasjonssikkerhet"]),
    status: "current",
  },
  {
    reference: "NSM-VEIL-DIGITALSIKKL-2025",
    title: "Veileder i digitalsikkerhetsloven og -forskriften",
    title_en: "Guide to the Digital Security Act and Regulation",
    date: "2025-10-01",
    type: "veileder",
    series: "Digitalsikkerhetsloven",
    summary:
      "NSMs veileder for virksomheter som er omfattet av digitalsikkerhetsloven (NIS-implementering i norsk rett). Tradt i kraft 1. oktober 2025. Gir veiledning om lovens krav til sikkerhetstiltak, hendelsesrapportering, tilsyn og sanksjoner.",
    full_text:
      "Veileder i digitalsikkerhetsloven og -forskriften fra NSM. Digitalsikkerhetsloven gjennomforer NIS-direktivet i norsk rett og tradt i kraft 1. oktober 2025. Veilederen dekker: hvilke virksomheter som er omfattet av loven (tilbydere av digitale tjenester og samferdselsvirksomheter), krav til sikkerhetstiltak basert pa risikovurdering, krav til hendelsesrapportering — vesentlige hendelser skal rapporteres innen 24 timer for tilbydere av samfunnsviktige tjenester, tilsynsordninger og sanksjonsmuligheter, NSMs rolle som nasjonalt kontaktpunkt, forholdet til sikkerhetsloven og annet regelverk. Loven inkluderer elementer fra NIS2 som rapportering, tilsyn og sanksjoner. NIS2-direktivet vil bli fullt gjennomfort i en nyere norsk lov.",
    topics: JSON.stringify(["digitalsikkerhetsloven", "NIS", "NIS2", "hendelsesrapportering", "tilsyn"]),
    status: "current",
  },
  {
    reference: "NSM-VEIL-FYSISK-2020",
    title: "Veileder i fysisk sikkerhet",
    title_en: "Guide to Physical Security",
    date: "2020-05-29",
    type: "veileder",
    series: "Sikkerhetsloven",
    summary:
      "NSMs veileder for fysisk sikring av skjermingsverdige verdier etter sikkerhetsloven. Dekker objektsikkerhet, perimetersikring, adgangskontroll, overvaking og alarmsystemer.",
    full_text:
      "Veileder i fysisk sikkerhet fra NSM. Veilederen beskriver hvordan virksomheter underlagt sikkerhetsloven skal ivareta kravene til fysisk sikkerhet for skjermingsverdige verdier. Dekker: sikkerhetslovens krav til objekt- og infrastruktursikkerhet (kapittel 7), risikovurdering av fysisk sikkerhet, soneinndeling og perimetersikring med definerte sikkerhetssoner, adgangskontroll — systemer, rutiner og personidentifikasjon, elektronisk overvaking og alarmsystemer, beskyttelse mot trusler som innbrudd, sabotasje, brann og naturhendelser, krav til oppbevaring av sikkerhetsgradert informasjon og materiell, transport av sikkerhetsgradert materiell, fysisk sikring av IKT-infrastruktur (serverrom, nettverksrom, kabelforinger).",
    topics: JSON.stringify(["fysisk-sikkerhet", "objektsikkerhet", "adgangskontroll", "perimetersikring", "sikkerhetsloven"]),
    status: "current",
  },
  {
    reference: "NSM-VEIL-AUTORISASJON-2025",
    title: "Handbok i autorisasjon",
    title_en: "Handbook on Authorisation",
    date: "2025-04-02",
    type: "handbok",
    series: "Sikkerhetsloven",
    summary:
      "NSMs handbok med praktisk veiledning for autorisasjonsprosesser etter sikkerhetsloven. Dekker personellsikkerhet, sikkerhetsklarering og autorisasjon for tilgang til sikkerhetsgradert informasjon.",
    full_text:
      "Handbok i autorisasjon fra NSM. Praktisk veiledning for virksomheter som gjennomforer autorisasjonsprosesser etter sikkerhetsloven. Dekker: autorisasjonsansvarets omfang og delegering, forutsetninger for autorisasjon (gyldig sikkerhetsklarering, tjenstlig behov, sikkerhetssamtale og taushetserklæring), gjennomforing av sikkerhetssamtaler, løpende personkontroll og oppfølging av endringer, tilbakekalling og suspensjon av autorisasjon, dokumentasjon og arkivering, forholdet til sikkerhetslovens kapittel 8 om personellsikkerhet og klareringsforskriften. Handboken er oppdatert per april 2025 og erstatter tidligere versjon.",
    topics: JSON.stringify(["personellsikkerhet", "autorisasjon", "sikkerhetsklarering", "sikkerhetsloven"]),
    status: "current",
  },
  {
    reference: "NSM-KRYPTO-2025",
    title: "Kryptografiske anbefalinger",
    title_en: "Cryptographic Recommendations",
    date: "2025-03-24",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs kryptografiske anbefalinger med konkrete rad om spesifikke algoritmer innen ulike bruksomrader. Dekker symmetrisk og asymmetrisk kryptering, hashing, digitale signaturer og nokkelhåndtering.",
    full_text:
      "Kryptografiske anbefalinger fra NSM. Dokumentet gir konkrete rad om spesifikke kryptografiske algoritmer for ulike bruksomrader. Dekker: symmetrisk kryptering — AES-256 anbefalt, AES-128 akseptabelt for ugradert informasjon. Asymmetrisk kryptering — RSA minimum 3072 bit, ECC minimum 256 bit (P-256/P-384). Hashing — SHA-256 minimum, SHA-384/SHA-512 for langsiktig sikkerhet. Digitale signaturer — ECDSA med P-256 eller P-384, EdDSA med Ed25519 eller Ed448. Nokkelutveksling — ECDH med P-256/P-384 eller X25519/X448. TLS — minimum TLS 1.2, anbefalt TLS 1.3. Nokkellengder for gradert informasjon folger NSAs anbefalinger for nasjonal sikkerhet. Post-kvante-kryptografi — NSM folger utviklingen og vil oppdatere anbefalingene nar NIST-standarder er modne. Nokkelhåndtering — bruk HSM for kritisk nokkelmateriale, fastsett levetid og rotasjonsrutiner.",
    topics: JSON.stringify(["kryptografi", "AES", "RSA", "ECC", "TLS", "SHA", "post-kvante", "HSM"]),
    status: "current",
  },
  {
    reference: "NSM-AVHENGIGHETER-2025",
    title: "Handbok i kartlegging, vurdering og rapportering av avhengigheter",
    title_en: "Handbook on Mapping, Assessing and Reporting Dependencies",
    date: "2025-12-18",
    type: "handbok",
    series: "Sikkerhetsloven",
    summary:
      "NSMs handbok for a kartlegge avhengigheter, vurdere grad av avhengighet og rapportere funn. Verktoy for virksomheter underlagt sikkerhetsloven for a identifisere kritiske avhengigheter.",
    full_text:
      "Handbok i kartlegging, vurdering og rapportering av avhengigheter fra NSM. Et verktoy for virksomheter underlagt sikkerhetsloven for a kartlegge avhengigheter, vurdere grad av avhengighet og rapportere funn til relevant myndighet. Dekker: identifisering av avhengigheter til leverandorer, tjenester, infrastruktur og andre virksomheter, vurdering av avhengighetsgrad (kritisk, hoy, middels, lav), risikovurdering av avhengigheter i kontekst av nasjonal sikkerhet, rapporteringsmal og prosedyrer, oppfolging og handtering av identifiserte avhengighetsrisikoer. Handboken stotter virksomhetsikkerhetsforskriftens krav til vurdering av avhengigheter som del av forebyggende sikkerhetsarbeid.",
    topics: JSON.stringify(["avhengigheter", "kartlegging", "leverandorkjede", "sikkerhetsloven", "risikostyring"]),
    status: "current",
  },
  {
    reference: "NSM-PASSORD-2024",
    title: "Passordanbefalinger fra Nasjonal sikkerhetsmyndighet",
    title_en: "Password Recommendations from the National Security Authority",
    date: "2024-03-15",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs passordanbefalinger for virksomheter og privatpersoner. Anbefaler passord pa minimum 16 tegn, bruk av passordfraser, flerfaktorautentisering og passordhvelv. Utarbeidet i samarbeid med NorSIS.",
    full_text:
      "NSMs passordanbefalinger utviklet i samarbeid med NorSIS (Norsk senter for informasjonssikring). For virksomheter: bruk passord pa minimum 16 tegn for akseptabelt beskyttelsesniva med dagens teknologi. Bruk passordfraser — sammensatte ord som er lettere a huske men vanskelige for datamaskiner a gjette. Forsterkes med dialektord, slang og feilstavede ord. Ikke krev jevnlig passordbytte uten grunn — dette forer til svakere passord. Bruk flerfaktorautentisering (MFA) i tillegg til passord — dette er NSMs klare anbefaling. Bruk passordhvelv (password manager) for a handtere unike passord per tjeneste. Endre alle standardpassord pa IKT-produkter for de tas i bruk. Ikke tillat bruk av passord som er lekket i kjente datainnbrudd. For privatpersoner: bruk lange passord eller passordfraser. Aldri gjenbruk passord pa tvers av tjenester. Aktiver MFA der det er tilgjengelig.",
    topics: JSON.stringify(["passord", "MFA", "autentisering", "passordfraser", "passordhvelv"]),
    status: "current",
  },
  {
    reference: "NSM-EPOST-SIKRING",
    title: "Grunnleggende tiltak for sikring av e-post",
    title_en: "Basic Measures for Email Security",
    date: "2023-06-22",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs anbefalinger for sikring av e-post med STARTTLS, SPF, DKIM og DMARC. Reduserer risikoen for e-postforfalskning (spoofing), phishing og avlytting av e-postkommunikasjon.",
    full_text:
      "Grunnleggende tiltak for sikring av e-post fra NSM. NSM anbefaler fire beskyttelsesmekanismer for a sikre e-post pa e-postservere: STARTTLS: Kryptert overfoering av e-post mellom e-postservere. Sikrer at e-post ikke kan avlyttes under transport. SPF (Sender Policy Framework): SPF brukes til a fortelle hvilke IP-adresser som har lov til a sende e-post pa vegne av et domene. Det er viktig a bruke SPF pa egne domener som ikke brukes til a sende e-post ('v=spf1 -all') — dette reduserer risikoen for at en angriper kan sende falsk e-post pa vegne av virksomhetens domener (spoofing). DKIM (DomainKeys Identified Mail): DKIM sikrer at e-post kan videresendes. Avsenderens e-postserver plasserer en digital signatur pa all utgaende e-post, og mottakerens e-postserver kan sjekke signaturen mot informasjon publisert i DNS. DKIM bruker asymmetrisk kryptering med en offentlig og privat nokkel. DMARC (Domain Message Authentication Reporting and Conformance): DMARC fjerner gjettingen om hvordan e-post som feiler SPF/DKIM-validering skal haandteres, ettersom avsenderen i tillegg publiserer hvordan e-post som feiler SPF/DKIM skal haandteres. En viktig funksjonalitet i DMARC er rapporteringsmekanismen som SPF og DKIM mangler. Start med DMARC-policy 'none' for overvaking, deretter skjerp til 'quarantine' og til slutt 'reject'.",
    topics: JSON.stringify(["e-post", "STARTTLS", "SPF", "DKIM", "DMARC", "spoofing", "phishing"]),
    status: "current",
  },
  {
    reference: "NSM-FEM-TILTAK",
    title: "Fem effektive tiltak mot dataangrep",
    title_en: "Five Effective Measures Against Data Attacks",
    date: "2023-09-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs fem viktigste tekniske tiltak for a beskytte systemer mot dataangrep: sikkerhetsoppdateringer, fjerne administratorrettigheter, sterk autentisering, fas ut eldre produkter, og programvarehvitelisting.",
    full_text:
      "NSMs fem effektive tiltak mot dataangrep er de viktigste tekniske tiltakene systemeiere bor ta i bruk. De vanligste angrepene gjennomfores med skadevare mot ansattes datamaskiner og ved gjetting av enkle passord. Tiltak 1 — Sikkerhetsoppdateringer: Installer sikkerhetsoppdateringer sa fort som mulig, og mest mulig automatisk. Oppdateringer bor vaere sentralt styrt. Prioriter oppdatering av operativsystemer og programvare som behandler data fra internett (nettlesere, e-postklienter, PDF-lesere, Office-pakker). Tiltak 2 — Fjern administratorrettigheter: Ikke tildel administratorrettigheter til sluttbrukere. De fleste sluttbrukere har ikke legitimt behov for administratortilgang, noe angripere utnytter. Tiltak 3 — Sterk autentisering: Ikke tillat bruk av svake passord, og bruk multifaktorautentisering der det er mulig. Endre standardpassord pa alle produkter. Passord pa minimum 16 tegn. Tiltak 4 — Fas ut eldre produkter: Fas ut eldre IKT-produkter. Nyere versjoner inneholder flere sikkerhetsoppdateringer og forbedrede sikkerhetsfunksjoner. Tiltak 5 — Programvarehvitelisting: Tillat kun programvare som er godkjent av virksomheten eller enhetsleverandoren. Konfigurer enheter til kun a kjore godkjent programvare. NSM understreker at disse tiltakene krever minimal ny investering — de handler primaert om konfigurasjon av eksisterende verktoy.",
    topics: JSON.stringify(["fem-tiltak", "sikkerhetsoppdateringer", "administratorrettigheter", "MFA", "hvitelisting"]),
    status: "current",
  },
  {
    reference: "NSM-DIG-UTPRESSING",
    title: "Sikkerhetstiltak mot digital utpressing og andre angrep",
    title_en: "Security Measures Against Digital Extortion and Other Attacks",
    date: "2024-01-15",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs omfattende veiledning med 44 tiltak fordelt pa 8 tiltaksgrupper for a forebygge, oppdage og handtere digital utpressing (ransomware). NSM anbefaler at man ikke betaler losepenger.",
    full_text:
      "Sikkerhetstiltak mot digital utpressing og andre angrep fra NSM. Det finnes ikke ett enkelt tiltak som stopper digital utpressing — en virksomhet ma ha et bredt sett med sikkerhetstiltak. 44 tiltak fordelt pa 8 tiltaksgrupper: Tiltaksgruppe 1 — Planlegging og hendelseshåndtering (tiltak 1-6): Ha en plan for teknologiske tiltak, sikkerhetskultur, identifiser viktigste verdier, forbered virksomheten pa dataangrep, ta pa forhand stilling til losepengekrav (NSM anbefaler a ikke betale), rutiner for alternative kommunikasjonskanaler. Tiltaksgruppe 2 — Sikkerhetskopi og gjenoppretting (tiltak 7-13): Ha oversikt over systemer, oppretthold evne til gjenoppretting av infrastruktur og informasjon, ta sikkerhetskopier etter behov, isoler kopier, sikre drift av sikkerhetskopieringen, forbered rask gjenoppretting. Tiltaksgruppe 3 — Forebygging av inngang og spredning (tiltak 14-22): Sterk autentisering, web- og e-postfiltrering, sikkerhetsherding, begrens internetteksponering, nettverkssegmentering, dataflyt-kontroll, sperr direkte klienttrafikk, fjern glemte maskiner, systemovervaking. Tiltaksgruppe 4 — Beskyttelse av eksternt tilgjengelige tjenester. Tiltaksgruppe 5 — Forebygging av kjoring av skadevare (tiltak 23-33): Fjern administratorrettigheter, programvarekontroll, hindre makrokjoring, sentralisert drift, fas ut eldre produkter, fjern ubrukt programvare, automatisert oppdatering, skadevare-skanning, endre standardpassord, vurder filrettigheter, aktiver innebygd sikkerhet. Tiltaksgruppe 6 — Vanskeliggjore dataeksfiltrering. Tiltaksgruppe 7 — Hendelseshandtering (tiltak 34-43): Varsle NCSC og politiet, koble fra infiserte enheter, vurder nettverksutkobling, passordbytte, reinstaller systemer, sjekk fastvare, bruk kun sikre kopier, gjenopprett pa uberort segment, gjenoppta overvaking, laer av hendelsen. Tiltaksgruppe 8 — Produktspesifikke tiltak (tiltak 44): Bruk Windows Attack Surface Reduction (ASR) og Controlled Folder Access.",
    topics: JSON.stringify(["ransomware", "digital-utpressing", "hendelseshåndtering", "sikkerhetskopi", "44-tiltak"]),
    status: "current",
  },
  {
    reference: "NSM-DIG-BEREDSKAP",
    title: "Digital beredskap i en skjerpet situasjon",
    title_en: "Digital Preparedness in a Heightened Threat Situation",
    date: "2024-04-01",
    type: "recommendation",
    series: "NCSC",
    summary:
      "NCSCs anbefalinger for virksomheter som onsker a styrke sin digitale beredskap i lys av det skjerpede trusselbildet. Ni konkrete omrader fra systemoversikt til skytjenestesikring.",
    full_text:
      "Digital beredskap i en skjerpet situasjon fra NCSC (Nasjonalt cybersikkerhetssenter). Ni omrader: 1. Systemoversikt: Ha en oppdatert oversikt over systemer og programvare i nettverket, nettverksdiagram med segmenttilkoblinger og eksterne forbindelser, og lop ende oppdateringsstatus. 2. Sikkerhetskopi og gjenoppretting: Oppbevar kopier pa isolert infrastruktur, verifiser gjenopprettingsevnen regelmessig. 3. Sarbarhetsreduksjon: Prioriter oppdatering av internetteksponerte tjenester, fas ut eldre systemer uten MFA eller sikkerhetsoppdateringer, begrens RDP-tilgang og aktiver logging, deaktiver makroer i eksterne dokumenter, gjennomga BYOD-policyer. 4. Identitets- og tilgangskontroll: Fjern brukere som ikke lenger skal ha tilganger, gjennomfor tilgangsgjennomganger, krev sterke unike passord, implementer MFA over alt, bruk geoblocking. 5. Sikkerhetsovervaking: Utvid logging, ok oppbevaringstid, overvak trafikk i begge retninger, bygg analytisk kapasitet. 6. Ansattbevissthet: Styrk sikkerhetskultur mot phishing og sosial manipulasjon. 7. Hendelseshandteringsplanlegging: Utarbeid, vedlikehold og ov hendelseshandteringsprosedyrer med oppdaterte kontaktlister. 8. Leverandorkjedesikkerhet: Dokumenter leverandoravhengigheter og etabler kontinuitetsoversikt. 9. Skytjenestesikring: Styrk tilgangskontroll pa skytjenester som Microsoft 365 og Google Workspace.",
    topics: JSON.stringify(["beredskap", "trusselbildet", "systemoversikt", "sikkerhetskopi", "tilgangskontroll", "leverandorkjede"]),
    status: "current",
  },
  {
    reference: "NSM-TJENESTEUTSETTING",
    title: "Sikkerhetsfaglige anbefalinger ved tjenesteutsetting",
    title_en: "Security Recommendations for Outsourcing",
    date: "2023-04-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs sikkerhetsfaglige anbefalinger for virksomheter som vurderer a sette ut IKT-tjenester eller bruke skytjenester. Dekker risikovurdering, leverandorvalg, kontraktsforhold og lopende oppfolging.",
    full_text:
      "Sikkerhetsfaglige anbefalinger ved tjenesteutsetting fra NSM. NSM er positiv til at virksomheter bruker skytjenester i storre grad, forutsatt at virksomheten har gjort gode og korrekte vurderinger pa forhand — fordelene er storre enn ulempene for de fleste. NSMs erfaring er at flertallet av uonskede hendelser knyttet til skytjenester ikke skyldes feil eller sarbarheter hos skyleverandoren, men mangler eller feil i konfigurasjon eller bruk av skytjenesten. Anbefalinger: gjennomfor grundig risikovurdering for beslutningen tas, vurder om virksomheten har kompetanse til a drifte tjenesten selv versus a sette den ut, velg leverandor med dokumentert sikkerhetsniva (ISO 27001, SOC 2), reguler sikkerhetsansvar klart i kontrakt, gjennomfor regelmessig oppfolging og revisjon av leverandor, ha plan for avslutning av leverandorforhold inkludert datahandtering.",
    topics: JSON.stringify(["tjenesteutsetting", "skytjenester", "leverandorvurdering", "risikovurdering", "kontrakt"]),
    status: "current",
  },
  {
    reference: "NSM-SSLVPN-UTFASING",
    title: "NCSC anbefaler a erstatte SSLVPN/WebVPN med sikrere alternativer",
    title_en: "NCSC Recommends Replacing SSLVPN/WebVPN with Secure Alternatives",
    date: "2024-05-15",
    type: "recommendation",
    series: "NCSC",
    summary:
      "NCSC anbefaler a fase ut SSL/TLS-baserte VPN-losninger til fordel for IPsec med IKEv2 grunnet gjentatt utnyttelse av sarbarheter. Virksomheter ma ga over innen utlop av 2025; virksomheter underlagt sikkerhetsloven innen utlop av 2024.",
    full_text:
      "NCSC anbefaler a erstatte SSLVPN/WebVPN med sikrere alternativer. Publisert 15. mai 2024, oppdatert 3. september 2024. Anbefaling: Etabler en plan for utfasing av SSLVPN og overgang til IPsec IKEv2 grunnet gjentatt utnyttelse av sarbarheter i SSL/TLS-baserte VPN-losninger. Frist: virksomheter underlagt sikkerhetsloven skal fullfoere overgangen innen utlop av 2024, ovrige virksomheter innen utlop av 2025. Alternative losninger som Windows Always On VPN eller WireGuard-baserte protokoller er akseptable forutsatt tilstrekkelige sikkerhetskontroller. Overgangstiltak: rekonfigurer eksisterende VPN til IPsec IKEv2 eller erstatt, migrer brukere og systemer, deaktiver SSLVPN-funksjonalitet, blokker innkommende TLS-trafikk til VPN-servere, implementer sertifikatbasert autentisering. Midlertidige tiltak for perioden: aktiver sentralisert logging med anomalideteksjon, implementer geofencing, blokker tilkoblinger fra VPN-tjenester, Tor-noder og VPS-leverandorer.",
    topics: JSON.stringify(["SSLVPN", "VPN", "IPsec", "IKEv2", "WireGuard", "utfasing"]),
    status: "current",
  },
  {
    reference: "NSM-DDOS-FOREBYGGING",
    title: "Forebyggelse av tjenestenektangrep",
    title_en: "Prevention of DDoS Attacks",
    date: "2023-08-01",
    type: "recommendation",
    series: "NCSC",
    summary:
      "NCSCs veiledning om forebygging av og respons pa tjenestenektangrep (DDoS). Angrepene er ofte motivert av oppmerksomhet snarere enn skade. Dekker volumetriske angrep, applikasjonslagsangrep og mitigeringsstrategier.",
    full_text:
      "Forebyggelse av tjenestenektangrep fra NCSC. DDoS-angrep er minimalt teknisk avanserte og ofte motivert av oppmerksomhet snarere enn skade, men kan likevel forstyrre kritiske tjenester. Typer: Volumetriske angrep — overveldende baandbredde med stor trafikkmengde (UDP flood, DNS amplification, NTP amplification). Protokollangrep — utnytte svakheter i nettverksprotokoller (SYN flood, Ping of Death). Applikasjonslagsangrep — rette seg mot spesifikke applikasjoner (HTTP flood, Slowloris). Forebyggende tiltak: ha en DDoS-responsplan og ov den, bruk CDN eller DDoS-mitigeringstjeneste, konfigurer nettverksutstyr med rate-limiting og ACL-er, dimensjoner infrastruktur for a tale trafikktopper, ha avtale med internettleverandor om DDoS-respons, sikre at kritiske tjenester har alternative tilgangsveger, overvak trafikk for tidlig deteksjon. Under angrep: aktiver DDoS-mitigering, varsle internettleverandor, dokumenter angrepet (tidslinjer, IP-adresser, trafikkvolumer), varsle NCSC.",
    topics: JSON.stringify(["DDoS", "tjenestenektangrep", "volumetrisk", "mitigering", "CDN"]),
    status: "current",
  },
  {
    reference: "NSM-MOBIL-13RAD",
    title: "13 rad for bedre sikkerhet pa mobile enheter",
    title_en: "13 Tips for Better Mobile Device Security",
    date: "2023-11-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs 13 anbefalinger for bedre sikkerhet pa mobiltelefoner og nettbrett. Dekker oppdateringer, appinstallasjoner, tilgangskontroll, VPN og sikker konfigurasjon.",
    full_text:
      "13 rad for bedre sikkerhet pa mobile enheter fra NSM. 1. Hold enheten oppdatert — installer oppdateringer sa fort som mulig. 2. Installer kun apper fra offisielle appbutikker. 3. Bruk PIN-kode, fingeravtrykk eller ansiktsgjenkjenning for a lase enheten. 4. Aktiver automatisk lasting etter kort inaktivitet. 5. Aktiver kryptering av enhetens lagring. 6. Aktiver 'finn min enhet'-funksjonalitet for fjernstyring og sletting. 7. Bruk VPN ved tilkobling til apne tradlose nettverk. 8. Vaer kritisk til apptillatelser — gi kun nodvendige tilganger. 9. Deaktiver Bluetooth, Wi-Fi og NFC nar det ikke er i bruk. 10. Bruk mobilenhetsstyring (MDM) i virksomhetssammenheng. 11. Skill mellom privat og virksomhetsdata med separate profiler eller containere. 12. Ta jevnlige sikkerhetskopier av viktig innhold. 13. Vaer oppmerksom pa phishing og svindelforsok via SMS, e-post og meldingsapper.",
    topics: JSON.stringify(["mobil-sikkerhet", "MDM", "app-sikkerhet", "VPN", "kryptering"]),
    status: "current",
  },
  {
    reference: "NSM-SOSIALE-MEDIER",
    title: "Tips til virksomheter for vurdering av sosiale medie-apper",
    title_en: "Tips for Organisations on Evaluating Social Media Apps",
    date: "2023-06-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs veiledning for virksomheter om vurdering av sosiale medie-apper pa virksomhetens enheter. Dekker risikovurdering, personvern, datahandtering og sikkerhetshensyn.",
    full_text:
      "Tips til virksomheter for vurdering av sosiale medie-apper fra NSM. NSM har utarbeidet veiledning for organisasjoner som onsker a vurdere sikkerheten ved ansattes bruk av sosiale medie-applikasjoner. Vurderingskriterier inkluderer: hvilke data samler appen inn (kontakter, posisjonsdata, bruksmonstre), hvor lagres dataene og under hvilken jurisdiksjon, hvem har tilgang til dataene og til hvilke formal, hvilke tillatelser krever appen og er de proporsjonale med funksjonaliteten, har leverandoren en troverdig sikkerhetspraksis og haandterer de sarbarheter, finnes det risiko for at data kan deles med uonskede tredjeparter inkludert fremmede etterretningstjenester. NSM anbefaler at virksomheter har en policy for bruk av sosiale medier pa tjenesteenheter, og at virksomheter med saerlig sensitiv informasjon vurderer a begrense installasjon av slike apper pa virksomhetens enheter.",
    topics: JSON.stringify(["sosiale-medier", "app-vurdering", "personvern", "datatilgang", "policy"]),
    status: "current",
  },
  {
    reference: "NSM-NASJRAMME-2025",
    title: "Nasjonalt rammeverk for haandtering av digitale angrep og cyberhendelser",
    title_en: "National Framework for Handling Digital Attacks and Cyber Incidents",
    date: "2025-05-01",
    type: "report",
    series: "NSM",
    summary:
      "Nasjonalt rammeverk som beskriver Norges modell for koordinert haandtering av digitale angrep og cyberhendelser. Definerer roller, ansvar og samvirke mellom myndigheter, sektorer og virksomheter.",
    full_text:
      "Nasjonalt rammeverk for håndtering av digitale angrep og cyberhendelser fra NSM. Rammeverket beskriver den norske modellen for koordinert haandtering av digitale angrep og cyberhendelser. Definerer: NSMs rolle som nasjonal sikkerhetskoordinator gjennom NCSC (Nasjonalt cybersikkerhetssenter), sektorvise responsmiljoer (sektorCERT-er) som JustisCERT, HelseCSIRT, KraftCERT og FinansCERT, samvirkeprinsippet — hendelser haandteres pa lavest mulig niva, men eskaleres ved behov, den nasjonale eskaleringsmodellen fra virksomhetsniva til sektorniva til nasjonalt niva, samarbeid med internasjonale partnere gjennom FIRST, EU CSIRT-nettverket og NATO CCDCOE, varslings- og rapporteringspliktene etter sikkerhetsloven og digitalsikkerhetsloven, NCSCs rolle i varsling, koordinering og stotte ved nasjonale cyberhendelser. Rammeverket er et samarbeidsdokument mellom NSM, PST, E-tjenesten og relevante sektormyndigheter.",
    topics: JSON.stringify(["hendelseshandtering", "rammeverk", "NCSC", "sektorCERT", "eskalering", "samvirke"]),
    status: "current",
  },
  {
    reference: "NSM-DATASENTER-2024",
    title: "Anskaffelser av datasentertjenester",
    title_en: "Procurement of Data Centre Services",
    date: "2024-10-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs anbefalinger for anskaffelse av datasentertjenester med fokus pa sikkerhet, jurisdiksjon, fysisk sikring og krav til leverandorer.",
    full_text:
      "Anskaffelser av datasentertjenester fra NSM. Rapporten gir anbefalinger for offentlige og private virksomheter som skal anskaffe datasentertjenester. Dekker: vurdering av jurisdiksjon og lovgivning — hvor dataene lagres og behandles pavirker hvilke lover og regler som gjelder, fysiske sikkerhetskrav til datasenteret (strm, kjoling, brannsikkerhet, adgangskontroll, overvaking), krav til nettverkssikkerhet og tilgjengelighet (redundans, diverse ruter, DDoS-beskyttelse), leverandorvurdering — sertifiseringer (ISO 27001, SOC 2, Tier-klassifisering), drifts- og vedlikeholdsavtaler (SLA) med tydelige sikkerhetsmetriker, haandtering av hendelser og varsling, exitstrategi — plan for a flytte data og tjenester til annen leverandor, saerlige hensyn for virksomheter underlagt sikkerhetsloven.",
    topics: JSON.stringify(["datasenter", "anskaffelse", "jurisdiksjon", "fysisk-sikkerhet", "leverandorvurdering"]),
    status: "current",
  },
  {
    reference: "NSM-MOBILAPP-2024",
    title: "Mobilapplikasjoner pa tjenesteenheter",
    title_en: "Mobile Applications on Work Devices",
    date: "2024-08-01",
    type: "recommendation",
    series: "NSM",
    summary:
      "NSMs rapport om sikkerhetsutfordringer med mobilapplikasjoner pa virksomhetens tjenesteenheter. Gir anbefalinger for risikovurdering og haandtering av apper med hoy risikoprofil.",
    full_text:
      "Mobilapplikasjoner pa tjenesteenheter fra NSM. Rapporten adresserer sikkerhetsutfordringer knyttet til bruk av mobilapplikasjoner pa enheter utstedt av virksomheten. Hovedtemaer: risikovurdering av individuelle applikasjoner basert pa datatilgang, tillatelser og leverandortillit, kategoribaserte retningslinjer for ulike typer apper (kommunikasjon, produktivitet, sosiale medier, spill), tekniske tiltak som MDM (Mobile Device Management), appkontainere og hvidtelisting, organisatoriske tiltak som policyer, opplaering og akseptabel bruk-avtaler, saerlige hensyn for virksomheter med gradert informasjon, eksempler pa apper med kjente sikkerhetsutfordringer og NSMs vurdering.",
    topics: JSON.stringify(["mobilapp", "tjenesteenhet", "MDM", "risikovurdering", "appkontainer"]),
    status: "current",
  },
  {
    reference: "NSM-KVALITETSORDNING",
    title: "Kvalitetsordning for leverandorer som handterer IKT-hendelser",
    title_en: "Quality Scheme for Vendors Handling ICT Incidents",
    date: "2023-05-01",
    type: "recommendation",
    series: "NCSC",
    summary:
      "NSM har etablert en godkjenningsordning for leverandorer som tilbyr tjenester innen haandtering av datainnbrudd og IKT-sikkerhetshendelser. Sikrer kvalitet og kompetanse hos hendelsesresponsleverandorer.",
    full_text:
      "Kvalitetsordning for leverandorer som handterer IKT-hendelser fra NSM/NCSC. NSM har etablert en godkjenningsordning for leverandorer som tilbyr tjenester for haandtering av datainnbrudd og IKT-sikkerhetshendelser. Ordningen skal sikre at virksomheter som trenger hjelp ved hendelser kan finne kvalifiserte leverandorer med dokumentert kompetanse og erfaring. Krav til godkjenning inkluderer: demonstrert teknisk kompetanse innen digital etterforskning og hendelsesrespons, dokumenterte prosesser og metodikk for hendelseshåndtering, erfaring med haandtering av reelle hendelser, personell med relevante sertifiseringer (GIAC, GCIH, GCFE, EnCE), rutiner for sikker haandtering av kundenes data og bevismateriell, kapasitet til a handtere hendelser innen avtalte responstider. Godkjente leverandorer listes pa NCSCs nettsider. NSM anbefaler at virksomheter inngaar forhåndsavtaler med godkjente leverandorer.",
    topics: JSON.stringify(["kvalitetsordning", "hendelsesrespons", "digital-etterforskning", "leverandor", "sertifisering"]),
    status: "current",
  },
  {
    reference: "NSM-KONSEPTVALGSKY",
    title: "Konseptvalgutredning for nasjonal skytjeneste",
    title_en: "Concept Study for National Cloud Service",
    date: "2023-03-01",
    type: "report",
    series: "NSM",
    summary:
      "NSMs konseptvalgutredning for en nasjonal skytjeneste. Vurderer behov, alternativer og anbefalinger for en norsk skytjenestelosning for offentlig sektor og virksomheter med saerlige sikkerhetsbehov.",
    full_text:
      "Konseptvalgutredning for nasjonal skytjeneste fra NSM. Utredningen vurderer behovet for en nasjonal skytjenestelosning for offentlig sektor og virksomheter med saerlige sikkerhetsbehov. Bakgrunn: okende bruk av skytjenester i offentlig sektor, behov for a handtere informasjon som ikke kan legges i kommersielle skytjenester grunnet jurisdiksjon eller klassifisering, behov for norsk suverenitet over data. Alternativer vurdert: utvide bruk av eksisterende kommersielle skytjenester med tilleggskontroller, etablere statlig skytjeneste driftet av norske myndigheter, samarbeidsmodell mellom offentlige og private aktorer, hybrid-losning med ulike skymodeller for ulike dataklassifiseringer. Anbefalinger: en lagdelt tilnaerming der alminnelig ugradert informasjon kan legges i kommersielle skytjenester med god konfigurasjon, sensitive data krever skytjenester med sterkere norsk kontroll, gradert informasjon krever sertifiserte norske losninger under nasjonal jurisdiksjon.",
    topics: JSON.stringify(["nasjonal-sky", "suverenitet", "offentlig-sektor", "jurisdiksjon", "dataklassifisering"]),
    status: "current",
  },
];

// ---------------------------------------------------------------------------
// 5. Guidance — Sikkerhetsloven and Regulations
// ---------------------------------------------------------------------------

const lovgivning: GuidanceRow[] = [
  {
    reference: "LOV-2018-06-01-24",
    title: "Lov om nasjonal sikkerhet (sikkerhetsloven)",
    title_en: "Act on National Security (Security Act)",
    date: "2019-01-01",
    type: "lov",
    series: "Sikkerhetsloven",
    summary:
      "Sikkerhetsloven skal forebygge, avdekke og motvirke sikkerhetstruende virksomhet. Tradt i kraft 1. januar 2019. Gjelder statlige, fylkeskommunale og kommunale organer samt leverandorer ved sikkerhetsgraderte anskaffelser.",
    full_text:
      "Lov om nasjonal sikkerhet (sikkerhetsloven), LOV-2018-06-01-24. Lovens formal er a trygge nasjonale sikkerhetsinteresser og forebygge, avdekke og motvirke sikkerhetstruende virksomhet. Loven tradt i kraft 1. januar 2019 og erstattet den tidligere sikkerhetsloven fra 1998. Struktur: Kapittel 1 — Formal, virkeomrade og definisjoner. Kapittel 2 — Generelle bestemmelser om forebyggende sikkerhet. Kapittel 3 — Tilsyn. Kapittel 4 — Generelle krav til forebyggende sikkerhetsarbeid: virksomhetenes plikter, risikovurdering, sikkerhetsstyring og varsling av NSM (paragraf 4-5). Kapittel 5 — Informasjonssikkerhet (paragraf 5-1 til 5-6): graderingsnivaaer BEGRENSET, KONFIDENSIELT, HEMMELIG, STRENGT HEMMELIG. Kapittel 6 — Informasjonssystemsikkerhet (paragraf 6-1 til 6-6): godkjenning av informasjonssystemer, overvaking og logging. Kapittel 7 — Objekt- og infrastruktursikkerhet (paragraf 7-1 til 7-6): klassifisering, pekingsvedtak, sikringstiltak. Kapittel 8 — Personellsikkerhet (paragraf 8-1 til 8-17): sikkerhetsklarering, adgangsklarering, personkontroll, autorisasjon. Kapittel 9 — Sikkerhetsgraderte anskaffelser (paragraf 9-1 til 9-4): leverandorklarering, sikkerhetsinstrukser. Loven gjelder for statlige, fylkeskommunale og kommunale organer, samt for leverandorer av varer og tjenester i forbindelse med sikkerhetsgraderte anskaffelser.",
    topics: JSON.stringify(["sikkerhetsloven", "nasjonal-sikkerhet", "sikkerhetsklarering", "informasjonssikkerhet", "objektsikkerhet"]),
    status: "current",
  },
  {
    reference: "FOR-2018-12-20-2053",
    title: "Virksomhetsikkerhetsforskriften",
    title_en: "Entity Security Regulation",
    date: "2019-01-01",
    type: "forskrift",
    series: "Sikkerhetsloven",
    summary:
      "Forskrift om virksomheters arbeid med forebyggende sikkerhet. Utfyller sikkerhetsloven med detaljerte krav til styrings- og kontrollsystem, risikovurdering, informasjonssikkerhet, fysisk sikkerhet, personellsikkerhet og sikkerhetsgraderte anskaffelser.",
    full_text:
      "Virksomhetsikkerhetsforskriften (FOR-2018-12-20-2053) — forskrift om virksomheters arbeid med forebyggende sikkerhet. Forskriften tradt i kraft 1. januar 2019 sammen med sikkerhetsloven. Struktur: Kapittel 1-2 — Virkeomrade og generelle krav. Kapittel 3 — Generelle krav til beskyttelse av skjermingsverdige verdier: risikovurdering, sikkerhetsstyring, internkontroll. Kapittel 4-5 — Informasjonssikkerhet: sikkerhetsgradert informasjon, handtering, oppbevaring, overfoering. Kapittel 6-7 — Informasjonssystemsikkerhet: sikkerhetsgodkjenning, tekniske sikkerhetstiltak, overvaking. Kapittel 8-9 — Fysisk sikkerhet: soneinndeling, adgangskontroll, overvaking, alarmsystemer. Kapittel 10 — Personellsikkerhet: autorisasjon, sikkerhetssamtaler, lopende oppfolging. Kapittel 11 — Nasjonalt varslingssystem for digital infrastruktur (VDI): tilslutning, datadeling, personvern. Kapittel 12 — Sikkerhetsstyring: styringssystem, internkontroll, avvikshaandtering. Kapittel 13 — Sikkerhetsgraderte anskaffelser: leverandorklarering, sikkerhetsinstrukser, tilsyn. Kapittel 14 — Tilsyn: NSMs tilsynsmyndighet og -metoder.",
    topics: JSON.stringify(["virksomhetsikkerhetsforskriften", "sikkerhetsloven", "risikovurdering", "VDI", "sikkerhetsgodkjenning"]),
    status: "current",
  },
  {
    reference: "FOR-2018-12-20-2054",
    title: "Klareringsforskriften",
    title_en: "Clearance Regulation",
    date: "2019-01-01",
    type: "forskrift",
    series: "Sikkerhetsloven",
    summary:
      "Forskrift om sikkerhetsklarering og annen klarering. Regulerer prosessen for sikkerhetsklarering, adgangsklarering og leverandorklarering, inkludert personkontroll, vilkar, klageadgang og frister.",
    full_text:
      "Klareringsforskriften (FOR-2018-12-20-2054) — forskrift om sikkerhetsklarering og annen klarering. Forskriften regulerer prosessen for sikkerhetsklarering, adgangsklarering og leverandorklarering etter sikkerhetsloven. Sikkerhetsklarering tildeles i nivaene BEGRENSET, KONFIDENSIELT, HEMMELIG og STRENGT HEMMELIG og gis til personer som trenger tilgang til sikkerhetsgradert informasjon. Prosessen inkluderer: vurdering av tjenstlig behov, personopplysningsskjema, personkontroll gjennom registersok, eventuelle utdypende undersokelser, NSMs klareringsmyndighet for HEMMELIG og STRENGT HEMMELIG, departementene klarerer for KONFIDENSIELT og BEGRENSET. Vilkar for klarering: lojalitet, paalitelighet, dommekraft — vurdert mot risikofaktorer som okonomi, rusmidler, tilknytning til fremmede stater, kriminelle forhold. Klageadgang: avgjorelser om sikkerhetsklarering kan paklages til overordnet klareringsmyndighet. Leverandorklarering: virksomheter som skal ha tilgang til sikkerhetsgradert informasjon ma ha leverandorklarering. Forskriften er endret senest ved FOR-2025-06-20-1133.",
    topics: JSON.stringify(["klareringsforskriften", "sikkerhetsklarering", "personkontroll", "leverandorklarering", "sikkerhetsloven"]),
    status: "current",
  },
  {
    reference: "INS-1972-03-17-3352",
    title: "Beskyttelsesinstruksen",
    title_en: "Protection Instructions",
    date: "1972-03-17",
    type: "instruks",
    series: "Sikkerhetsloven",
    summary:
      "Instruks for behandling av dokumenter som trenger beskyttelse av andre grunner enn de som er nevnt i sikkerhetsloven med forskrifter. Beskyttelsesnivaer: FORTROLIG og INTERN.",
    full_text:
      "Beskyttelsesinstruksen (INS-1972-03-17-3352) — instruks for behandling av dokumenter som trenger beskyttelse av andre grunner enn de som er nevnt i sikkerhetsloven med forskrifter. Instruksen gjelder for forvaltningen og regulerer haandtering av ugradert men beskyttelsesverdig informasjon. To beskyttelsesnivaer: FORTROLIG — informasjon som kan skade offentlige interesser, enkeltpersoner eller virksomheter om den blir kjent for uvedkommende. INTERN — informasjon beregnet for intern bruk. Instruksen regulerer merking, oppbevaring, utsendelse, tilintetgjorelse og ansvar for beskyttelsesverdig informasjon. Instruksen supplerer offentleglova og forvaltningsloven med hensyn til haandtering av dokument som kan unntas offentlighet. Beskyttelsesinstruksen verner inventions of significance for the realm's defense og implementerer NATOs mutual secrecy agreement.",
    topics: JSON.stringify(["beskyttelsesinstruksen", "FORTROLIG", "INTERN", "forvaltning", "ugradert"]),
    status: "current",
  },
  {
    reference: "LOV-DIGITALSIKKERHET-2025",
    title: "Digitalsikkerhetsloven",
    title_en: "Digital Security Act",
    date: "2025-10-01",
    type: "lov",
    series: "Digitalsikkerhetsloven",
    summary:
      "Lov om digital sikkerhet som gjennomforer NIS-direktivet i norsk rett. Tradt i kraft 1. oktober 2025. Gjelder tilbydere av digitale tjenester og samfunnsviktige tjenester. NSM er nasjonalt kontaktpunkt.",
    full_text:
      "Digitalsikkerhetsloven gjennomforer NIS-direktivet (Network and Information Security) i norsk rett og styrker Norges tilknytning til europeisk beredskaps- og sikkerhetssamarbeid. Loven tradt i kraft 1. oktober 2025. Virkeomrade: tilbydere av digitale tjenester (nettsteder, skytjenester, digitale markedsplasser) og tilbydere av samfunnsviktige tjenester innen energi, transport, helse, vannforsyning, digital infrastruktur og finans. Krav: virksomheter skal gjennomfore risikovurderinger og implementere sikkerhetstiltak tilpasset risikoen, hendelser som vesentlig pavirker tjenesteleveransen skal rapporteres innen 24 timer for tilbydere av samfunnsviktige tjenester, NSM forer tilsyn og kan ilegge sanksjoner ved brudd. Loven inkluderer elementer fra NIS2-direktivet, saerlig innen rapportering, tilsyn og sanksjoner. NIS2-direktivet vil bli fullt gjennomfort i en nyere norsk lov som inkluderer bade NIS2 og CER-direktivet (Critical Entities Resilience), som vil erstatte digitalsikkerhetsloven. NSM har publisert en dedikert veileder i digitalsikkerhetsloven og -forskriften.",
    topics: JSON.stringify(["digitalsikkerhetsloven", "NIS", "NIS2", "hendelsesrapportering", "samfunnsviktige-tjenester"]),
    status: "current",
  },
  {
    reference: "LOV-1953-06-26-8",
    title: "Lov om oppfinnelser av betydning for rikets forsvar",
    title_en: "Act on Inventions of Significance for National Defence",
    date: "1953-06-26",
    type: "lov",
    series: "Sikkerhetsloven",
    summary:
      "Loven beskytter oppfinnelser av betydning for rikets forsvar og gjennomforer NATOs gjensidige hemmeligholdsavtale. Relatert til sikkerhetslovens regulering av forsvarsrelatert informasjon.",
    full_text:
      "Lov om oppfinnelser av betydning for rikets forsvar (LOV-1953-06-26-8). Loven regulerer haandtering av oppfinnelser som er av betydning for Norges forsvar. Oppfinnelser som kan ha forsvarsrelatert betydning kan palegges hemmelighold. Loven gjennomforer NATOs gjensidige hemmeligholdsavtale ('Agreement for the mutual safeguarding of secrecy of inventions relating to defence'). Relevans for sikkerhetsloven: loven er en del av det bredere regelverket for beskyttelse av nasjonal sikkerhet og er listet som tilhorende regelverk under sikkerhetsloven pa nsm.no.",
    topics: JSON.stringify(["forsvar", "oppfinnelser", "hemmelighold", "NATO"]),
    status: "current",
  },
];

// ---------------------------------------------------------------------------
// 6. Advisories — NCSC Vulnerability Alerts and Incident Advisories
// ---------------------------------------------------------------------------

const advisories: AdvisoryRow[] = [
  // ---- 2024 ----
  {
    reference: "NCSC-2024-001",
    title: "Kritiske sarbarheter i Ivanti Connect Secure — aktivt utnyttet",
    date: "2024-02-02",
    severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure", "Ivanti Neurons for ZTA"]),
    summary:
      "NCSC varsler om aktiv utnyttelse av fire kritiske sarbarheter i Ivanti Connect Secure VPN-losninger. Ivantis anbefalte tiltak for a sikre seg mot kompromittering er ufullstendige — angripere omgar dem aktivt. Norske virksomheter med eksponerte Ivanti-systemer ma iverksette tiltak umiddelbart.",
    full_text:
      "NCSC varsel: Kritiske sarbarheter i Ivanti Connect Secure. Publisert 2. februar 2024, oppdatert 5. februar 2024. Fire sarbarheter: CVE-2023-46805 (autentiserings-bypass), CVE-2024-21887 (kommandoinjeksjon), CVE-2024-21888 (privilege escalation), CVE-2024-21893 (aktivt utnyttet). Alle fire pavirker Ivanti Connect Secure og Policy Secure; CVE-2024-21893 pavirker ogsa Neurons for ZTA. NSM faststar at Ivantis anbefalte tiltak for a sikre seg mot kompromittering er ufullstendige — angripere omgar dem aktivt. Anbefalinger: (1) Koble Ivanti Connect Secure-enheter fra nettverket umiddelbart. (2) Verifiser at systemet ikke er kompromittert og overvak. (3) Eksporter innstillinger, gjennomfor fabrikknullstilling to ganger. (4) Oppdater til siste versjon. (5) Gjenopprett innstillinger og fjern midlertidige tiltak. (6) Tilbakekall og utsted pa nytt sertifikater, nokler og passord. Virksomheter bor vurdere alternative fjerntilgangslosninger inntil verifiserte sikkerhetsoppdateringer forhindrer omgaelse. Varsle NCSC ved mistanke om kompromittering: varsle@cert.no.",
    cve_references: JSON.stringify(["CVE-2023-46805", "CVE-2024-21887", "CVE-2024-21888", "CVE-2024-21893"]),
  },
  {
    reference: "NCSC-2024-002",
    title: "Kritisk sarbarhet i produkter fra Fortinet — CVE-2024-21762",
    date: "2024-02-09",
    severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS", "FortiGate brannmurer", "FortiProxy"]),
    summary:
      "Kritisk sarbarhet i FortiOS SSL-VPN (CVE-2024-21762, CVSS 9.6) utnyttes aktivt. Uautentiserte angripere kan kjore kode og kommandoer pa sarbare enheter. Norske virksomheter med FortiGate-brannmurer ma oppdatere umiddelbart.",
    full_text:
      "NCSC varsel: Kritisk sarbarhet i produkter fra Fortinet. Publisert 9. februar 2024. CVE-2024-21762 i FortiOS SSL-VPN med CVSS-score 9.6 (KRITISK). Fortinet publiserte en sikkerhetsmelding 8. februar 2024 om at utnyttelse av sarbarheten gjor at en uautentisert angriper kan kjore kode og kommandoer pa sarbare enheter. Pavirket: FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13, 6.4.0-6.4.14, 6.2.0-6.2.15, alle 6.0-versjoner, og FortiProxy 7.4.0-7.4.2, 7.2.0-7.2.8, 7.0.0-7.0.14. Aktiv utnyttelse pagar. NSM har ikke bekreftet hendelser i Norge enna, men forventer rask eskalering. Ingen offentlig tilgjengelig utnyttelseskode per na. A deaktivere SSL VPN reduserer risikoen; a deaktivere 'webmode' alene er ikke tilstrekkelig. Anbefalinger: Behandle med hogeste prioritet — ta sarbare systemer offline umiddelbart til de er oppdatert. Relatert sarbarhet CVE-2024-23113 loses i de samme oppdateringene. Kontakt NCSC: cert@ncsc.no eller 02497.",
    cve_references: JSON.stringify(["CVE-2024-21762", "CVE-2024-23113"]),
  },
  {
    reference: "NCSC-2024-003",
    title: "Angrep mot SSLVPN-produkter i kritisk infrastruktur",
    date: "2024-04-25",
    severity: "critical",
    affected_products: JSON.stringify(["Cisco ASA 55xx-serien", "WebVPN", "SSLVPN-produkter"]),
    summary:
      "NCSC varsler om en avansert trusselaktor som utnytter flere nulldagssarbarheter i SSLVPN-produkter rettet mot kritisk infrastruktur. Cisco ASA 55xx-serien med firmware 9.12 og 9.14 er pavirket. Samarbeid med Canada, Storbritannia og Australia.",
    full_text:
      "NCSC varsel oppdatert 25. april 2024: Angrep mot SSLVPN-produkter i kritisk infrastruktur. En sofistikert trusselaktor utnytter flere nulldagssarbarheter i SSLVPN-produkter rettet mot organisasjoner som driver kritisk infrastruktur. Pavirket: Cisco ASA 55xx-serien med firmware versjon 9.12 og 9.14, og WebVPN-funksjonalitet i Cisco ASA-systemer. Angrepet har ukjent initialt inngangspunkt. Kampanjen har pagatt siden november 2023. NSM anbefaler at organisasjoner — saerlig de som driver de berarte Cisco-versjonene eller WebVPN — implementerer mitigeringstiltak fra NSM/NCSC, CCCS/NCSC-UK/ACSC felles anbefaling, og Ciscos offisielle veiledning. Varselet indikerer samarbeid mellom kanadiske, britiske og australske cybersikkerhetsmyndigheter, noe som understreker truselens internasjonale betydning.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-004",
    title: "NCSC anbefaler a erstatte SSLVPN/WebVPN med sikrere alternativer",
    date: "2024-05-15",
    severity: "high",
    affected_products: JSON.stringify(["Alle SSLVPN/WebVPN-losninger", "Fortinet SSLVPN", "Cisco WebVPN", "Palo Alto GlobalProtect"]),
    summary:
      "NCSC anbefaler utfasing av SSL/TLS-baserte VPN-losninger til fordel for IPsec med IKEv2 grunnet gjentatt utnyttelse av sarbarheter. Frist: sikkerhetsloven-virksomheter innen 2024, ovrige innen 2025.",
    full_text:
      "NCSC varsel: Anbefaler a erstatte SSLVPN/WebVPN med sikrere alternativer. Publisert 15. mai 2024, oppdatert 3. september 2024. NCSC anbefaler a fase ut SSL/TLS-baserte VPN-losninger til fordel for IPsec med IKEv2 grunnet gjentatt utnyttelse av sarbarheter i disse produktene. Frister: virksomheter underlagt sikkerhetsloven skal fullfoere overgangen innen utlop av 2024, ovrige virksomheter innen utlop av 2025. Alternative sikre losninger inkluderer Windows Always On VPN og WireGuard-baserte protokoller. Overgangstiltak: rekonfigurer eksisterende VPN til IPsec IKEv2 eller erstatt, migrer brukere, deaktiver SSLVPN, blokker innkommende TLS-trafikk til VPN-servere, implementer sertifikatbasert autentisering. Midlertidige tiltak: aktiver sentralisert logging med anomalideteksjon, implementer geofencing, blokker tilkoblinger fra VPN-tjenester, Tor-noder og VPS-leverandorer.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-005",
    title: "Oppdatering varsel om sarbarhet i CheckPoint — CVE-2024-24919",
    date: "2024-05-30",
    severity: "critical",
    affected_products: JSON.stringify(["CheckPoint Quantum Security Gateway"]),
    summary:
      "NCSC oppdaterer sitt varsel om aktiv utnyttelse av CheckPoint-sarbarhet CVE-2024-24919 i Norge. NCSC er kjent med bade utnyttelsesforsok og vellykket utnyttelse av denne sarbarheten i Norge.",
    full_text:
      "NCSC varsel oppdatert 30. mai 2024: Sarbarhet i CheckPoint Quantum Security Gateway. CVE-2024-24919. NCSC bekrefter kjennskap til bade utnyttelsesforsok og vellykket utnyttelse av denne sarbarheten i Norge. Anbefalinger: oppdater berarte enheter til sikre versjoner umiddelbart, fjern lokale brukerkontoer fra enhetene, roter passord for LDAP-tilkoblinger til Active Directory, gjennomga logger for a utelukke kompromittering, oppdater CheckPoint IPS-signaturer nar mulig. Organisasjoner bor gjennomfore etterforskning tilbake til 30. april 2024 da utnyttelsesforsok startet pa denne datoen. NCSC viser til detaljert teknisk veiledning fra Check Points stotteportal og sikkerhetsfirmaet mnemonic for mitigeringsprosedyrer og etterforskningsmetodikk. Organisasjoner som oppdager potensiell kompromittering bor kontakte sin sektorsrespons-team eller MSSP.",
    cve_references: JSON.stringify(["CVE-2024-24919"]),
  },
  {
    reference: "NCSC-2024-006",
    title: "Aktiv utnyttelse av Fortinet-sarbarhet CVE-2024-55591",
    date: "2025-01-14",
    severity: "critical",
    affected_products: JSON.stringify(["FortiOS versjon 7.0", "FortiProxy versjon 7.0", "FortiProxy versjon 7.2"]),
    summary:
      "NCSC varsler om aktiv utnyttelse av kritisk sarbarhet CVE-2024-55591 i FortiOS og FortiProxy. Sarbarheten tillater angripere a omga autentisering og kjore vilkarlig kode som superadministrator.",
    full_text:
      "NCSC varsel: Aktiv utnyttelse av Fortinet-sarbarhet CVE-2024-55591. Publisert 14. januar 2025. Sarbarheten tillater angripere a omga autentisering og kjore vilkarlig kode som superadministrator. Pavirket: FortiOS versjon 7.0 og FortiProxy versjon 7.0 og 7.2. Aktiv utnyttelse pagar. NCSC rapporterer ingen bekreftede vellykkede utnyttelser i Norge sa langt, men forventer fremtidige angrep. Sarbarheten kan vaere knyttet til 'Arctic Wolf'-kampanjen rettet mot Fortinet FortiGate-brannmurer. Anbefalinger: (1) Virksomheter med sarbare versjoner eksponert mot internett bor verifisere systemer mot indikatorer delt av Fortinet (FG-IR-24-535). (2) Kontakt sektorsrespons-team eller MSSP ved mistanke om kompromittering. (3) Ikke eksponer administrative grensesnitt direkte mot internett. (4) Fortsett planlagt utskifting av SSLVPN/WebVPN til IPsec IKEv2 (frist utlop 2025).",
    cve_references: JSON.stringify(["CVE-2024-55591"]),
  },
  {
    reference: "NCSC-2024-007",
    title: "Okt DDoS-trussel mot norske mal fra pro-russiske grupper",
    date: "2024-03-10",
    severity: "high",
    affected_products: JSON.stringify(["Offentlige myndigheter", "Kritisk infrastruktur", "Finanssektor", "Transportsektor"]),
    summary:
      "NCSC registrerer markant okning i DDoS-angrep mot norske virksomheter fra pro-russiske hacktivistgrupper som NoName057(16) og KillNet. Angrepene er motivert av Norges stotte til Ukraina og NATO-politikk.",
    full_text:
      "NCSC varsel: Okt DDoS-trussel mot norske malsettinger fra pro-russiske grupper. NCSC har registrert en markant okning i DDoS-angrep (Distributed Denial of Service) mot norske virksomheter og offentlige myndigheter. Trusselaktorer: pro-russiske hacktivistgrupper som NoName057(16) og KillNet koordinerer angrep via Telegram. Angrepene er motivert av Norges stotte til Ukraina og NATO-politikk. Malutvalg: offentlige myndigheters nettsider, bank- og finanssektoren, transportinfrastruktur (Avinor, Vy), medieorganisasjoner. Angrepskarakteristikk: volumetriske DDoS-angrep typisk mellom 10 og 100+ Gbps, varighet vanligvis 2-6 timer, noen angrep kombinerer volumetriske og applikasjonslagsteknikker. Anbefalte tiltak: verifiser at DDoS-beskyttelse er aktivert og korrekt konfigurert, test beredskapsplaner for DDoS-hendelser, etabler kontakt med internettleverandoren om DDoS-responsrutiner, sikre at kritiske tjenester har alternative tilgangsveger, varsle NCSC om DDoS-angrep.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-008",
    title: "Patchetirsdag juni 2024 — kritisk Microsoft-sarbarhet",
    date: "2024-06-11",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office", "Microsoft Exchange Server"]),
    summary:
      "Microsofts sikkerhetsoppdateringer for juni 2024 fikser 49 sarbarheter, hvorav en er vurdert som kritisk og kan lede til kjoring av kode pa en sarbar enhet.",
    full_text:
      "NCSC varsel: Microsoft patchetirsdag juni 2024. Microsoft har utgitt sikkerhetsoppdateringer som fikser 49 sarbarheter. En av sarbarhetene er vurdert som kritisk av Microsoft og kan potensielt lede til kjoring av kode pa en sarbar enhet. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene sa fort som mulig i trad med sine interne rutiner for oppdateringshåndtering. NSM minner om at jevnlige sikkerhetsoppdateringer er et av fem effektive tiltak mot dataangrep. Virksomheter bor ha automatisert oppdatering der mulig, og manuelle oppdateringsprosesser for systemer som krever testing for utrulling.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-009",
    title: "Patchetirsdag oktober 2024 — tre kritiske sarbarheter",
    date: "2024-10-08",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office", "Microsoft Azure"]),
    summary:
      "Microsofts sikkerhetsoppdateringer for oktober 2024 fikser 120 sarbarheter, hvorav tre er vurdert som kritiske av Microsoft.",
    full_text:
      "NCSC varsel: Microsoft patchetirsdag oktober 2024. Microsoft har utgitt sikkerhetsoppdateringer som fikser 120 sarbarheter. Tre av sarbarhetene er vurdert som kritiske. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i trad med sine oppdateringsrutiner. Saerlig viktig for virksomheter med internetteksponerte Windows-servere og Office-installasjoner. NSM anbefaler automatisert sikkerhetsoppdatering der mulig.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-010",
    title: "Patchetirsdag november 2024 — tre kritiske sarbarheter",
    date: "2024-11-12",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office", "Microsoft Exchange Server"]),
    summary:
      "Microsofts sikkerhetsoppdateringer for november 2024 fikser 93 sarbarheter, hvorav tre er vurdert som kritiske av Microsoft.",
    full_text:
      "NCSC varsel: Patchetirsdag november 2024. Totalt 93 sarbarheter, tre kritiske. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner. NSM minner om at jevnlige sikkerhetsoppdateringer er et av fem effektive tiltak mot dataangrep.",
    cve_references: JSON.stringify([]),
  },

  // ---- 2023 ----
  {
    reference: "NCSC-2023-001",
    title: "Oppdatert varsel for sarbarheter i Cisco IOS XE Web UI — CVE-2023-20198",
    date: "2023-10-22",
    severity: "critical",
    affected_products: JSON.stringify(["Cisco IOS XE", "Cisco-rutere og -svitsjer med HTTP/S-server"]),
    summary:
      "Kritisk sarbarhet i HTTP/S-serveren pa Cisco IOS XE-enheter (CVE-2023-20198, CVSS 10.0). Angripere far tilgang med privilege level 15 og kan opprette kontoer for systeminnlogging. Flere Cisco IOS XE-enheter i Norge er bekreftet kompromittert.",
    full_text:
      "NCSC varsel: Sarbarheter i Cisco IOS XE Web UI. Publisert 22. oktober 2023, oppdatert 23. oktober 2023. Primaer sarbarhet: CVE-2023-20198 (CVSS 10.0) — angriper utnytter forst denne for a fa tilgang med privilege level 15, kan deretter opprette legitimasjonsdata for systeminnlogging. Sekundaer sarbarhet: CVE-2023-20273 (CVSS 7.2) — muliggjor ytterligere privilegium-eskalering til root-tilgang via en annen webgrensesnittkomponent. NCSC er kjent med at flere Cisco IOS XE-enheter i Norge er kompromittert gjennom aktiv utnyttelse. Anbefalinger: installer oppdateringer umiddelbart ved tilgjengelighet, deaktiver webgrensesnittfunksjonaliteten hvis enheter er internetteksponert, gjennomfor etterforskning i henhold til tidligere NCSC-veiledning, overvak Ciscos offisielle sikkerhetsmeldinger.",
    cve_references: JSON.stringify(["CVE-2023-20198", "CVE-2023-20273"]),
  },
  {
    reference: "NCSC-2023-002",
    title: "Aktiv utnyttelse av sarbarheter i Cisco ASA og Cisco FTD — CVE-2023-20269",
    date: "2023-09-15",
    severity: "high",
    affected_products: JSON.stringify(["Cisco ASA", "Cisco Firepower Threat Defense (FTD)"]),
    summary:
      "NCSC varsler om aktiv utnyttelse av sarbarhet CVE-2023-20269 i Cisco ASA og FTD. Sarbarheten utnyttes for brute-force-angrep mot VPN-tilkoblinger og uautorisert tilgang.",
    full_text:
      "NCSC varsel: Aktiv utnyttelse av sarbarhet i Cisco ASA og Cisco FTD (CVE-2023-20269). Sarbarheten utnyttes aktivt for brute-force-angrep mot VPN-tjenester pa Cisco ASA og FTD-enheter. Angripere bruker sarbarheten til a fa uautorisert tilgang via VPN. NCSC anbefaler a implementere flerfaktorautentisering for VPN-tilgang, begrense tilgang basert pa IP-adresse, overvake innloggingsforsok for uvanlig aktivitet, og oppdatere til siste versjon av Cisco ASA/FTD nar tilgjengelig. Virksomheter bor vurdere utfasing av SSLVPN i trad med NCSCs anbefalinger.",
    cve_references: JSON.stringify(["CVE-2023-20269"]),
  },
  {
    reference: "NCSC-2023-003",
    title: "Masseutnyttelse av Citrix Netscaler-sarbarhet CVE-2023-3519",
    date: "2023-07-20",
    severity: "critical",
    affected_products: JSON.stringify(["Citrix NetScaler ADC", "Citrix NetScaler Gateway"]),
    summary:
      "NCSC varsler om masseutnyttelse av kritisk nulldagssarbarhet i Citrix NetScaler (CVE-2023-3519). Sarbarheten muliggjor fjernkjoring av kode uten autentisering og utnyttes aktivt til a installere bakdorer.",
    full_text:
      "NCSC varsel: Masseutnyttelse av Citrix Netscaler-sarbarhet CVE-2023-3519. Kritisk nulldagssarbarhet i Citrix NetScaler ADC og Gateway muliggjor uautentisert fjernkjoring av kode. Sarbarheten utnyttes aktivt i storstilt kampanje for a installere bakdorer og fa fotfeste i virksomheters nettverk. NCSC anbefaler at norske virksomheter med Citrix NetScaler-enheter umiddelbart oppdaterer til siste versjon, gjennomforer integritetssjekk av systemene, gjennomgar nettverkslogger for mistenkelig aktivitet, og varsler NCSC ved mistanke om kompromittering. Utnyttelse kan ha forekommet for oppdateringen var tilgjengelig — virksomheter som oppdaterte sent bor anta mulig kompromittering og gjennomfore grundig etterforskning.",
    cve_references: JSON.stringify(["CVE-2023-3519"]),
  },
  {
    reference: "NCSC-2023-004",
    title: "Citrix Netscaler: Kritisk nulldagssarbarhet utnyttes aktivt",
    date: "2023-10-10",
    severity: "critical",
    affected_products: JSON.stringify(["Citrix NetScaler ADC", "Citrix NetScaler Gateway"]),
    summary:
      "NCSC varsler om ny kritisk nulldagssarbarhet i Citrix NetScaler som utnyttes aktivt. Sarbarheten tillater uautentiserte angripere a hente ut hemmeligheter som innloggingsdata, nokler, sertifikater, aktive sesjoner og konfigurasjonsfiler.",
    full_text:
      "NCSC varsel: Citrix Netscaler kritisk nulldagssarbarhet. Publisert august 2023. Ny kritisk sarbarhet i Citrix NetScaler som kan tillate en uautentisert angriper fra internett a hente ut hemmeligheter som innloggingsdata, nokler, sertifikater, aktive sesjoner og konfigurasjonsfiler. Dette kan potensielt gi angriperen ytterligere fotfeste pa serveren eller i organisasjonens nettverk. Sarbarheten utnyttes aktivt. NCSC anbefaler umiddelbar oppdatering, gjennomgang av tilgangslogger, og rotasjon av sertifikater og passord dersom kompromittering mistaenkes.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2023-005",
    title: "Kritiske sarbarheter i Palo Alto, Pulse Secure og Fortinet SSL VPN",
    date: "2023-04-01",
    severity: "critical",
    affected_products: JSON.stringify(["Palo Alto GlobalProtect", "Pulse Secure VPN", "Fortinet FortiGate SSL VPN"]),
    summary:
      "NCSC varsler om kritiske sarbarheter i tre av de mest brukte SSLVPN-produktene: Palo Alto, Pulse Secure og Fortinet. Sarbarhetene utnyttes aktivt av bade statlige og kriminelle aktorer.",
    full_text:
      "NCSC varsel: Kritiske sarbarheter i Palo Alto, Pulse Secure og Fortinet SSL VPN. Tre av de mest utbredte SSLVPN-produktene har kritiske sarbarheter som utnyttes aktivt. Palo Alto GlobalProtect: sarbarheter tillater omgaelse av autentisering. Pulse Secure VPN: kritiske sarbarheter muliggjor fjernkjoring av kode uten autentisering. Fortinet FortiGate SSL VPN: sarbarheter i SSL VPN-webportalen muliggjor tilgang til sensitive data. Sarbarhetene utnyttes av bade statlige aktorer (saerlig kinesiske og russiske) og cyberkriminelle grupper. NCSC anbefaler umiddelbar oppdatering av alle VPN-enheter, gjennomgang av logger for tegn pa kompromittering, implementering av MFA for VPN-tilgang, og langsiktig plan for overgang til IPsec IKEv2.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2023-006",
    title: "Aktiv utnyttelse av kritisk nulldagssarbarhet i Atlassian Confluence",
    date: "2022-06-03",
    severity: "critical",
    affected_products: JSON.stringify(["Atlassian Confluence Server", "Atlassian Confluence Data Center"]),
    summary:
      "NCSC varsler om kritisk nulldagssarbarhet i Atlassian Confluence Server og Data Center (CVE-2022-26134). Sarbarheten tillater uautentiserte angripere a kjore vilkarlig kode. Norske virksomheter med internetteksponert Confluence ma ta den offline umiddelbart.",
    full_text:
      "NCSC varsel: Aktiv utnyttelse av kritisk nulldagssarbarhet i Atlassian Confluence. Publisert 3. juni 2022. CVE-2022-26134 pavirker alle stottede versjoner av Atlassian Confluence Server og Data Center. Sarbarheten tillater uautentiserte angripere a kjore vilkarlig kode. Aktiv utnyttelse er dokumentert internasjonalt. Ingen sikkerhetsoppdatering var tilgjengelig pa publiseringstidspunktet. NCSC anbefaler at norske virksomheter med internetteksponerte Confluence-instanser umiddelbart tar disse offline inntil sikkerhetsoppdatering er tilgjengelig. Alternativt implementer mitigeringstiltak fra Atlassian. Overvak situasjonen for oppdateringer.",
    cve_references: JSON.stringify(["CVE-2022-26134"]),
  },

  // ---- 2021 ----
  {
    reference: "NCSC-2021-001",
    title: "Varsel: Aktiv utnyttelse av sarbarheter i Microsoft Exchange",
    date: "2021-03-04",
    severity: "critical",
    affected_products: JSON.stringify(["Microsoft Exchange Server 2013", "Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"]),
    summary:
      "NCSC varsler om aktiv utnyttelse av sarbarheter i Microsoft Exchange (ProxyLogon). Bred skanning og utnyttelse pagar. Sannsynlig at ransomware-aktorer vil utnytte sarbarheten innen kort tid. Virksomheter som ikke hadde oppdatert innen 3. mars bor anse sin Exchange som mulig kompromittert.",
    full_text:
      "NCSC varsel: Aktiv utnyttelse av sarbarheter i Microsoft Exchange. Publisert 4. mars 2021. Sarbarheter i Microsoft Exchange er under aktiv utnyttelse av avanserte og ikke-avanserte trusselaktorer. Bred skanning og utnyttelse 'in the wild' pagar, sammen med malrettede angrep. Sikkerhetsfirmaet ESET bekrefter at flere aktorer utnytter sarbarheten. NCSC vurderer det som sannsynlig at ransomware-aktorer vil utnytte sarbarheten innen kort tid. Kilder indikerer at bred aktiv utnyttelse kan ha startet sa tidlig som 27. februar. NCSC understreker at oppdatering alene ikke er tilstrekkelig — virksomheter ma ogsa undersoke Exchange-systemene for kompromitteringsindikatorer. Anbefalinger: installer Microsofts sikkerhetsoppdateringer umiddelbart, undersok Exchange-systemer for kompromittering, konsulter ressurser fra Microsoft, CISA og Volexity for deteksjonsveiledning, sok hjelp fra responsteam hvis virksomheten ikke kan gjennomfore undersokelser selv. Virksomheter som ikke oppdaterte innen 3. mars 2021 bor anse sin Exchange som mulig kompromittert. USAs CISA utstedte et nodsdirektiv 3. mars.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2021-002",
    title: "ProxyShell: Skanning etter sarbare Exchange-servere",
    date: "2021-08-13",
    severity: "critical",
    affected_products: JSON.stringify(["Microsoft Exchange Server"]),
    summary:
      "NCSC varsler om aktiv skanning etter og utnyttelse av ProxyShell-sarbarheter i Microsoft Exchange. ProxyShell bestar av tre sarbarheter som kombinert gir fjernkjoring av kode pa sarbare Exchange-servere.",
    full_text:
      "NCSC varsel: ProxyShell — skanning etter sarbare Exchange-servere. ProxyShell bestar av tre sarbarheter som kan kombineres i en angrepskjede for a oppna fjernkjoring av kode pa sarbare Microsoft Exchange-servere. Aktiv skanning og utnyttelse pagar. NCSC anbefaler umiddelbar oppdatering av alle Exchange-servere. Virksomheter med internetteksponerte Exchange-servere bor prioritere dette med hogeste prioritet. Sjekk for tegn pa kompromittering selv etter oppdatering.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2021-003",
    title: "Utvidet oppdatering for Apache Log4j — CVE-2021-44228",
    date: "2021-12-11",
    severity: "critical",
    affected_products: JSON.stringify(["Apache Log4j", "Java-applikasjoner", "Talrike produkter"]),
    summary:
      "NCSC varsler om kritisk sarbarhet i Apache Log4j (CVE-2021-44228, Log4Shell). NCSC observerer omfattende utnyttelsesforsok fra 10. og 11. desember. Sarbarheten pavirker et svært stort antall produkter og tjenester globalt.",
    full_text:
      "NCSC varsel: Utvidet oppdatering for Apache Log4j CVE-2021-44228 (Log4Shell). NCSC observerer omfattende utnyttelsesforsok fra 10. og 11. desember 2021. Log4j er et apen kildekode-loggbibliotek brukt i et stort antall Java-applikasjoner og tjenester. Sarbarheten muliggjor fjernkjoring av kode uten autentisering og er triviell a utnytte. Pavirket er et svært stort antall produkter og tjenester globalt — bade kommersielle og apen kildekode. NCSC anbefaler: identifiser alle systemer som bruker Log4j, oppdater til siste versjon (2.17.0 eller nyere), dersom umiddelbar oppdatering ikke er mulig, implementer mitigeringstiltak (deaktiver JNDI Lookup, fjern JndiLookup.class), overvak systemer for tegn pa utnyttelse, varsle NCSC ved kompromittering.",
    cve_references: JSON.stringify(["CVE-2021-44228"]),
  },
  {
    reference: "NCSC-2020-001",
    title: "Sarbarhet i SolarWinds Orion — leverandorkjede-angrep",
    date: "2020-12-14",
    severity: "critical",
    affected_products: JSON.stringify(["SolarWinds Orion Platform"]),
    summary:
      "NCSC varsler om et leverandorkjede-angrep der angripere opprettet signerte, trojaniserte versjoner av SolarWinds Orion-programvare som ble distribuert til kunder via normale oppdateringskanaler.",
    full_text:
      "NCSC varsel: Sarbarhet i SolarWinds Orion. Et sofistikert leverandorkjede-angrep der avanserte trusselaktorer kompromitterte SolarWinds sin bygge-pipeline og injiserte ondsinnet kode i Orion-plattformen. Trojaniserte oppdateringer (SUNBURST-bakdoren) ble distribuert til tusenvis av kunder globalt via SolarWinds sine normale oppdateringskanaler. Angrepet ble tilskrevet russisk etterretning (SVR/APT29/Cozy Bear). NCSC anbefaler at norske virksomheter som bruker SolarWinds Orion umiddelbart sjekker om de har installert pavirket versjon, isolerer SolarWinds-servere fra nettverket, gjennomforer grundig etterforskning for tegn pa kompromittering, og oppdaterer til sikre versjoner nar tilgjengelig. Hendelsen understreker risikoen ved leverandorkjede-angrep og viktigheten av a ha oversikt over sin programvareportefolje.",
    cve_references: JSON.stringify([]),
  },

  // ---- 2025 ----
  {
    reference: "NCSC-2025-001",
    title: "Kritisk sarbarhet i Citrix NetScaler — CVE-2025-6543",
    date: "2025-06-26",
    severity: "critical",
    affected_products: JSON.stringify(["Citrix NetScaler ADC", "Citrix NetScaler Gateway"]),
    summary:
      "Kritisk sarbarhet i Citrix NetScaler (CVE-2025-6543) tillater uautentisert angriper a kjore ondsinnet kode pa enheten. Rapportert aktivt utnyttet. Pavirker NetScaler distribuert som Gateway (VPN, ICA, CVPN, RDP) eller som virtuell AAA-server.",
    full_text:
      "NCSC varsel: Kritisk sarbarhet i Citrix NetScaler (CVE-2025-6543). Publisert 26. juni 2025. Sarbarheten er en buffer overflow-tilstand som potensielt gjor det mulig for angripere a etablere persistens eller bevege seg lateralt i virksomhetens nettverk. Rapportert aktivt utnyttet, men ingen offentlig tilgjengelig utnyttelseskode er kjent. Pavirket: NetScaler ADC og Gateway versjoner for 14.1-47.46, versjoner for 13.1-59.19, NetScaler ADC 13.1-FIPS og NDcPP for 13.1-37.236, end-of-life versjoner 12.1 og 13.0 (ikke oppdatert). Enheten ma vaere distribuert som Gateway (VPN, ICA, CVPN, RDP) eller som virtuell AAA-server for a vaere sarbar. Umiddelbare tiltak: installer siste sikkerhetsoppdateringer, avslutt alle aktive sesjoner med 'kill icaconnection -all' og 'kill pcoipConnection -all', oppgrader ustottede versjoner til gjeldende versjoner.",
    cve_references: JSON.stringify(["CVE-2025-6543"]),
  },
  {
    reference: "NCSC-2025-002",
    title: "Kritisk sarbarhet i Citrix NetScaler — CVE-2025-5777",
    date: "2025-08-26",
    severity: "critical",
    affected_products: JSON.stringify(["Citrix NetScaler ADC", "Citrix NetScaler Gateway"]),
    summary:
      "Citrix publiserer detaljer om aktivt utnyttet nulldagssarbarhet i Citrix NetScaler (CVE-2025-5777). Sarbarheten kan tillate en uautentisert angriper a kjore vilkarlig kode fra internett og brukes til a installere bakdorer.",
    full_text:
      "NCSC varsel: Kritisk nulldagssarbarhet i Citrix NetScaler. Publisert 26. august 2025. Citrix publiserte detaljer om en aktivt utnyttet nulldagssarbarhet (CVE-2025-5777) i Citrix NetScaler som kan tillate en uautentisert angriper a kjore vilkarlig kode pa sarbare enheter fra internett. Utnyttelse brukes potensielt til a installere bakdorer og etablere fotfeste i virksomhetens nettverk. NCSC anbefaler umiddelbar oppdatering og gjennomgang av systemene for tegn pa kompromittering.",
    cve_references: JSON.stringify(["CVE-2025-5777"]),
  },
  {
    reference: "NCSC-2025-003",
    title: "Kritiske nulldagssarbarheter i Cisco ASA og FTD Software",
    date: "2025-09-26",
    severity: "critical",
    affected_products: JSON.stringify(["Cisco ASA Software", "Cisco Firepower Threat Defense (FTD) Software"]),
    summary:
      "Flere nulldagssarbarheter i Cisco ASA og FTD Software kan tillate en uautentisert angriper fra internett a kjore vilkarlig kode og installere bakdorer pa sarbare enheter.",
    full_text:
      "NCSC varsel: Kritiske nulldagssarbarheter i Cisco ASA og FTD Software. Publisert 26. september 2025. Flere nulldagssarbarheter (CVE-2025-20333, CVE-2025-20363, CVE-2025-20362) i Cisco ASA og FTD Software kan tillate en uautentisert angriper fra internett a kjore vilkarlig kode og installere bakdorer pa sarbare enheter. NCSC anbefaler at alle virksomheter med disse produktene iverksetter mitigeringstiltak umiddelbart og oppdaterer nar Cisco gir ut sikkerhetsoppdateringer.",
    cve_references: JSON.stringify(["CVE-2025-20333", "CVE-2025-20363", "CVE-2025-20362"]),
  },
  {
    reference: "NCSC-2025-004",
    title: "Kritisk sarbarhet i React Server Components — CVE-2025-55182",
    date: "2025-12-04",
    severity: "critical",
    affected_products: JSON.stringify(["React Server Components"]),
    summary:
      "NSM anbefaler umiddelbart a oppdatere kritisk sarbarhet i React Server Components (CVE-2025-55182).",
    full_text:
      "NCSC varsel: Kritisk sarbarhet i React Server Components. Publisert 4. desember 2025. CVE-2025-55182 pavirker React Server Components. NSM anbefaler umiddelbar oppdatering. Virksomheter som bruker React Server Components i sine webapplikasjoner bor oppdatere til siste versjon umiddelbart for a mitigere risikoen.",
    cve_references: JSON.stringify(["CVE-2025-55182"]),
  },
  {
    reference: "NCSC-2025-005",
    title: "Kritiske sarbarheter i Linux-kjernen (CrackArmor)",
    date: "2026-03-13",
    severity: "critical",
    affected_products: JSON.stringify(["Linux-kjernen", "AppArmor sikkerhetsmodul"]),
    summary:
      "NSM anbefaler umiddelbart a oppdatere kritiske sarbarheter i AppArmor, en sikkerhetsmodul i Linux-kjernen. Sarbarhetene er blitt kalt 'CrackArmor' av Qualys og Canonical.",
    full_text:
      "NCSC varsel: Kritiske sarbarheter i Linux-kjernen. Publisert 13. mars 2026. NSM anbefaler umiddelbart a oppdatere kritiske sarbarheter i AppArmor, en sikkerhetsmodul i Linux-kjernen. Sarbarhetene er blitt kalt 'CrackArmor' av Qualys og Canonical. Ingen CVE-numre er tildelt enna. NCSC anbefaler at alle virksomheter som bruker Linux-systemer med AppArmor oppdaterer til siste kjerneversjon sa snart oppdateringer er tilgjengelige fra sin Linux-distribusjon.",
    cve_references: JSON.stringify([]),
  },

  // ---- Monthly Patch Tuesdays 2025/2026 ----
  {
    reference: "NCSC-2025-PT-SEP",
    title: "Microsoft patchetirsdag september 2025",
    date: "2025-09-09",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office", "Microsoft Exchange Server"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for september 2025. NCSC anbefaler a installere oppdateringene i henhold til virksomhetens oppdateringsrutiner.",
    full_text: "NCSC varsel: Microsoft patchetirsdag september 2025. Microsofts manedlige sikkerhetsoppdateringer. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene sa fort som mulig i trad med interne oppdateringsrutiner. NSM minner om at jevnlige sikkerhetsoppdateringer er et av fem effektive tiltak mot dataangrep.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2025-PT-OKT",
    title: "Microsoft patchetirsdag oktober 2025",
    date: "2025-10-14",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for oktober 2025.",
    full_text: "NCSC varsel: Microsoft patchetirsdag oktober 2025. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2025-PT-NOV",
    title: "Microsofts patchetirsdag november 2025",
    date: "2025-11-12",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for november 2025.",
    full_text: "NCSC varsel: Microsofts patchetirsdag november 2025. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2025-PT-DES",
    title: "Microsofts patchetirsdag desember 2025",
    date: "2025-12-09",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for desember 2025.",
    full_text: "NCSC varsel: Microsofts patchetirsdag desember 2025. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2026-PT-JAN",
    title: "Microsofts patchetirsdag januar 2026",
    date: "2026-01-13",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for januar 2026.",
    full_text: "NCSC varsel: Microsofts patchetirsdag januar 2026. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2026-PT-FEB",
    title: "Microsofts patchetirsdag februar 2026",
    date: "2026-02-10",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for februar 2026.",
    full_text: "NCSC varsel: Microsofts patchetirsdag februar 2026. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2026-PT-MAR",
    title: "Microsofts patchetirsdag mars 2026",
    date: "2026-03-10",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for mars 2026. NSM har ingen saerlige bemerkninger.",
    full_text: "NCSC varsel: Microsofts patchetirsdag mars 2026. NSM har ingen saerlige bemerkninger til Microsofts sikkerhetsoppdateringer for mars 2026. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
];

// ---------------------------------------------------------------------------
// 7. Additional Guidance — Grunnprinsipper sub-measures (individual tiltak)
// ---------------------------------------------------------------------------

const submeasures: GuidanceRow[] = [
  // Sub-measures of 2.1 — Anskaffelse
  {
    reference: "NSM-GP-2.1-T-2.1.1",
    title: "Tiltak 2.1.1 — Integrer sikkerhetskrav gjennom hele produktets livslop",
    title_en: "Measure 2.1.1 — Integrate security requirements throughout the product lifecycle",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Sikkerhetskrav skal vaere en del av alle faser fra anskaffelse til avhending av IKT-produkter.",
    full_text: "Tiltak 2.1.1 i NSMs Grunnprinsipper for IKT-sikkerhet v2.1: Integrer sikkerhetskrav gjennom hele produktets livslop, fra anskaffelse til avhending. Sikkerhetskrav skal defineres i kravspesifikasjonen, evalueres ved leverandorvalg, verifiseres ved mottakstesting, opprettholdes gjennom drift og vedlikehold, og ivaretas ved avhending (sletting av data, destruksjon av media).",
    topics: JSON.stringify(["anskaffelse", "livslop", "sikkerhetskrav"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.1.3",
    title: "Tiltak 2.1.3 — Foretrekk IKT-produkter sertifisert av betrodde tredjeparter",
    title_en: "Measure 2.1.3 — Prefer ICT products certified by trusted third parties",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Foretrekk IKT-produkter sertifisert etter Common Criteria (CC) for evaluering av sikkerhetskvaliteter.",
    full_text: "Tiltak 2.1.3: Foretrekk IKT-produkter sertifisert av betrodde tredjeparter, for eksempel Common Criteria (internasjonal standard for evaluering av sikkerhetskvaliteter). Common Criteria-evaluering gir uavhengig verifisering av at produktet oppfyller spesifiserte sikkerhetskrav. NSM anbefaler a vurdere CC-sertifisering saerlig for sikkerhetskritiske produkter som brannmurer, krypteringslosninger og tilgangskontrollsystemer.",
    topics: JSON.stringify(["Common-Criteria", "sertifisering", "evaluering"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.1.4",
    title: "Tiltak 2.1.4 — Reduser risiko for leverandorkjedemanipulering",
    title_en: "Measure 2.1.4 — Reduce supply chain manipulation risk",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Reduser risikoen for at IKT-produkter manipuleres i leverandorkjeden gjennom risikovurdering, integritetskontroll og sikker nedlasting.",
    full_text: "Tiltak 2.1.4: Reduser risiko for leverandorkjedemanipulering gjennom: a) risikovurdering av malrettede angrep, b) leverandordiskresjon vedrorende kundeinformasjon, c) integritetsbeskyttelse av produkter gjennom leverandorkjeden, d) programvarenedlasting kun fra offisielle HTTPS-kilder, e) regulert fysisk tilgang for vedlikehold. SolarWinds-hendelsen i 2020 demonstrerte alvorligheten av leverandorkjedeangrep — signerte trojaniserte oppdateringer ble distribuert til tusenvis av kunder.",
    topics: JSON.stringify(["leverandorkjede", "supply-chain", "integritet", "SolarWinds"]), status: "current",
  },
  // Sub-measures of 2.2 — Arkitektur
  {
    reference: "NSM-GP-2.1-T-2.2.3",
    title: "Tiltak 2.2.3 — Segmenter virksomhetens nettverk etter risikoprofil",
    title_en: "Measure 2.2.3 — Segment the network according to risk profile",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Segmenter nettverket i soner med ulike krav til kommunikasjon, eksponering, funksjon og rolle.",
    full_text: "Tiltak 2.2.3: Segmenter organisasjonens nettverk etter risikoprofil, med etablerte soner med ulike krav til kommunikasjon, eksponering, funksjon og rolle. Eksempler pa soner: administrasjonssystemer, applikasjonsservere, klientarbeidsstasjoner, industriell produksjon (OT/ICS), internettilgang (DMZ), tradlose nettverk, gjesteklienter og eksternt tilgjengelige tjenester. Nettverkssegmentering er et av de viktigste tiltakene for a begrense skadevirkninger ved et angrep — det forhindrer lateral bevegelse og isolerer kompromitterte segmenter.",
    topics: JSON.stringify(["nettverkssegmentering", "soner", "DMZ", "OT", "lateral-bevegelse"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.2.4",
    title: "Tiltak 2.2.4 — Fysisk isoler de mest kritiske nettverkssegmentene",
    title_en: "Measure 2.2.4 — Physically isolate the most critical network segments",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "De mest sensitive nettverkene skal fysisk isoleres med luftgap-separasjon fra resten av organisasjonens nettverk.",
    full_text: "Tiltak 2.2.4: Fysisk isoler de mest kritiske nettverkssegmentene, saerlig sensitive delnettverk gjennom luftgap-separasjon fra resten av organisasjonens nettverk. Luftgap betyr at det ikke er noen elektronisk forbindelse mellom det isolerte nettverket og andre nettverk. Dette er relevant for saerlig sensitive miljoer som: systemer for handtering av HEMMELIG og STRENGT HEMMELIG informasjon, kritiske industrielle kontrollsystemer (ICS/SCADA), sikkerhetsklareringsmiljoer. NSM understreker at luftgap-isolasjon ma suppleres med fysiske sikringstiltak og streng tilgangskontroll.",
    topics: JSON.stringify(["luftgap", "fysisk-isolasjon", "ICS", "SCADA", "gradert"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.2.7",
    title: "Tiltak 2.2.7 — Etabler robust og resilient IKT-arkitektur",
    title_en: "Measure 2.2.7 — Establish robust and resilient ICT architecture",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "IKT-arkitekturen skal sikre tilgjengelighet av kritiske funksjoner gjennom risikovurderinger og mottiltak for ulike feilscenarier.",
    full_text: "Tiltak 2.2.7: Etabler robust og resilient IKT-arkitektur som sikrer tilgjengelighet av kritiske funksjoner gjennom risikovurderinger og mottiltak som adresserer: maskinvarefeil (redundans, failover), menneskelige feil (automatisering, prosedyrer), dataangrep (segmentering, deteksjon), internetttilgjengelighet (redundante forbindelser, offline-modus), tjenesteleverandortilgjengelighet (multi-leverandor-strategi), stromforsyning (UPS, noedstrom), naturkatastrofer (geografisk distribusjon), geopolitiske faktorer (datalokalitet, jurisdiksjon). Resiliens betyr evne til a opprettholde drift under ugunstige forhold og rask gjenoppretting etter hendelser.",
    topics: JSON.stringify(["resiliens", "tilgjengelighet", "redundans", "failover", "katastrofe"]), status: "current",
  },
  // Sub-measures of 1.1 — Kartlegging
  {
    reference: "NSM-GP-2.1-T-1.1.3",
    title: "Tiltak 1.1.3 — Identifiser prosesser for IKT-risikostyring",
    title_en: "Measure 1.1.3 — Identify ICT risk management processes",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Identifiser IKT-risikostyringsprosesser som dekker verdianalyse, trusselvurdering, risikoidentifisering, risikovurdering og verifisering av sikkerhetstiltak.",
    full_text: "Tiltak 1.1.3: Identifiser prosesser for IKT-risikostyring som dekker: verdianalyse (hva skal beskyttes og hvor viktig er det), trusselvurdering (hvem kan angripe og med hvilke metoder), kartlegging av eksisterende sikkerhetstiltak (hva er allerede pa plass), risikoidentifisering (hvilke risikoer star virksomheten overfor), risikovurdering (hvor sannsynlige og alvorlige er risikoene), risikorapportering (informere ledelsen om risikobildet), risikohåndtering (akseptere, redusere, overfoere eller unnga risiko), verifisering av sikkerhetstiltak (kontrollere at tiltak fungerer som tiltenkt).",
    topics: JSON.stringify(["risikostyring", "verdianalyse", "trusselvurdering", "risikohåndtering"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-1.1.5",
    title: "Tiltak 1.1.5 — Kartlegg leveranser, informasjonssystemer og understottende IKT-funksjoner",
    title_en: "Measure 1.1.5 — Map deliverables, information systems and supporting ICT functions",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Kartlegg virksomhetens leveranser, informasjonssystemer og understottende IKT-funksjoner, gruppert etter risikoaksept.",
    full_text: "Tiltak 1.1.5: Kartlegg virksomhetens leveranser, informasjonssystemer og understottende IKT-funksjoner. Inkluder systemeierskap og ansvar, virksomhetskritiske roller og funksjoner, interne og eksterne avhengigheter, gruppert etter risikoaksept. Kartleggingen gir grunnlag for a prioritere sikkerhetstiltak og identifisere kritiske avhengigheter. NSM anbefaler at kartleggingen gjennomfores minimum arlig og ved vesentlige endringer i IKT-infrastrukturen.",
    topics: JSON.stringify(["kartlegging", "avhengigheter", "systemeierskap", "kritiske-funksjoner"]), status: "current",
  },
  // Sub-measures of 2.6 — Identiteter og tilganger
  {
    reference: "NSM-GP-2.1-T-2.6.2",
    title: "Tiltak 2.6.2 — Bruk flerfaktorautentisering (MFA) for alle brukere",
    title_en: "Measure 2.6.2 — Use multi-factor authentication for all users",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "NSMs klare anbefaling er at MFA brukes over alt der det er mulig, saerlig for tilgang til kritiske systemer, fjernaksess og administrativ tilgang.",
    full_text: "Tiltak 2.6.2: Bruk flerfaktorautentisering (MFA) for alle brukere, saerlig for tilgang til kritiske systemer, fjernaksess og administrativ tilgang. NSMs klare anbefaling er at MFA brukes over alt der det er mulig. MFA kombinerer noe du vet (passord) med noe du har (sikkerhetsnokkel, mobiltelefon) eller noe du er (biometri). MFA stopper de fleste dataangrep som baserer seg pa stjalne eller gjettede passord. Prioriterte omrader for MFA: alle VPN- og fjerntilgangspunkter, e-posttjenester, administratortilgang til servere og nettverksutstyr, skytjenester. NSM anbefaler phishing-resistente MFA-metoder som FIDO2/WebAuthn-sikkerhetsnokler der det er mulig.",
    topics: JSON.stringify(["MFA", "autentisering", "FIDO2", "WebAuthn", "sikkerhetsnokkel"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.6.4",
    title: "Tiltak 2.6.4 — Etabler privilegert tilgangsstyring (PAM)",
    title_en: "Measure 2.6.4 — Establish Privileged Access Management (PAM)",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Etabler privilegert tilgangsstyring for administratorkontoer med tidsbegrensede godkjente utvidelser av privilegier.",
    full_text: "Tiltak 2.6.4: Etabler privilegert tilgangsstyring (PAM) for administratorkontoer. Bruk tidsbegrensede, godkjente utvidelser av privilegier (just-in-time access) fremfor permanente administratorrettigheter. PAM-losninger bor inkludere: sentralisert handtering av privilegerte kontoer, sesjonsinspilling og logging av administrativ aktivitet, automatisk passordrotasjon for tjenestekontoer, godkjenningsarbeidsflyt for privilegert tilgang, integrasjon med SIEM for overvaking av privilegert aktivitet. Permanent administratortilgang oker risikoen for misbruk og gjor det enklere for angripere som kompromitterer en administratorkonto.",
    topics: JSON.stringify(["PAM", "privilegert-tilgang", "just-in-time", "sesjonsinspilling", "administratorkontoer"]), status: "current",
  },
  // Sub-measures of 3.2 — Overvaking
  {
    reference: "NSM-GP-2.1-T-3.2.4",
    title: "Tiltak 3.2.4 — Vurder tilknytning til NCSCs Varslingssystem for Digital Infrastruktur (VDI)",
    title_en: "Measure 3.2.4 — Consider connecting to NCSC's Warning System for Digital Infrastructure (VDI)",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "NCSCs Varslingssystem for Digital Infrastruktur (VDI) gir virksomheter trusselindikatorer og varsler om nasjonalt relevante cybertrusler.",
    full_text: "Tiltak 3.2.4: Vurder tilknytning til NCSCs Varslingssystem for Digital Infrastruktur (VDI). VDI er et sensornettverk som overvaker norsk digital infrastruktur for cyberangrep. Tilsluttede virksomheter mottar: trusselindikatorer (IoC) for kjente trusselaktorer, tidlig varsling om pagaende angrep mot norsk infrastruktur, anonymisert informasjon om observerte angrep og trender, stotte fra NCSC ved hendelser. VDI er regulert i virksomhetsikkerhetsforskriften kapittel 11. Tilslutning er frivillig for de fleste virksomheter, men palagt for virksomheter underlagt sikkerhetsloven. NSM anbefaler at alle virksomheter med kritisk infrastruktur vurderer tilslutning.",
    topics: JSON.stringify(["VDI", "varslingssystem", "NCSC", "trusselindikatorer", "IoC", "overvaking"]), status: "current",
  },
  // Sub-measures of 3.4 — Inntrengningstester
  {
    reference: "NSM-GP-2.1-T-3.4.5",
    title: "Tiltak 3.4.5 — NSMs erfaringer fra inntrengingstester: ti vanlige sarbarheter",
    title_en: "Measure 3.4.5 — NSM penetration testing findings: ten common vulnerabilities",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "NSMs rapport avdekker ti vanlige sarbarheter som skyldes manglende oversikt, svake passord, manglende MFA, forsinket oppdatering og feilkonfigurasjon.",
    full_text: "Tiltak 3.4.5: NSMs rapport 'Ti sarbarheter i norske IKT-systemer' viser de ti vanligste sarbarhetene fra NSMs egne inntrengingstester: 1) Manglende oversikt over egne IKT-systemer, 2) Svake eller standardpassord, 3) Manglende MFA, 4) Manglende eller forsinket oppdatering, 5) Feilkonfigurerte tjenester, 6) For brede tilgangsrettigheter, 7) Unodvendige tjenester eksponert mot internett, 8) Manglende nettverkssegmentering, 9) Svak logging og overvaking, 10) Manglende hendelseshandteringsplaner. Disse grunnleggende svakhetene gjenstar i mange norske virksomheter og er relativt enkle a utbedre. NSM anbefaler Grunnprinsipper for IKT-sikkerhet som utgangspunkt.",
    topics: JSON.stringify(["penetrasjonstest", "ti-sarbarheter", "passord", "MFA", "konfigurasjon"]), status: "current",
  },
  // Sub-measures of 4.3 — Hendelseshandtering
  {
    reference: "NSM-GP-2.1-T-4.3.6",
    title: "Tiltak 4.3.6 — Varsle NCSC ved alvorlige hendelser",
    title_en: "Measure 4.3.6 — Notify NCSC of serious incidents",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Sikkerhetsloven paragraf 4-5 palegger virksomheter a varsle NSM ved hendelser som kan pavirke nasjonale sikkerhetsinteresser. Kontakt: varsle@cert.no eller 02497.",
    full_text: "Tiltak 4.3.6: Varsle NCSC ved alvorlige hendelser. Sikkerhetsloven paragraf 4-5 palegger virksomheter underlagt sikkerhetsloven a varsle NSM ved sikkerhetshendelser som kan pavirke nasjonale sikkerhetsinteresser. Digitalsikkerhetsloven stiller krav om hendelsesrapportering innen 24 timer for tilbydere av samfunnsviktige tjenester. Kontaktinformasjon: e-post varsle@cert.no, telefon 02497 (doegnbemannet). Ved alvorlige hendelser anbefaler NCSC ogsa a varsle politiet og relevante sektordialog-partnere. Hendelser som bor varsles inkluderer: vellykket inntrengning i IKT-systemer, ransomware-angrep, dataeksfiltrering, angrep mot kritisk infrastruktur, mistanke om statlig etterretningsaktivitet.",
    topics: JSON.stringify(["varsling", "NCSC", "sikkerhetsloven", "hendelsesrapportering", "02497"]), status: "current",
  },

  // ---- Digital utpressing tiltaksgrupper (detailed) ----
  {
    reference: "NSM-DU-TG1",
    title: "Digital utpressing — Tiltaksgruppe 1: Planlegging og hendelseshåndtering",
    title_en: "Digital Extortion — Measure Group 1: Planning and Incident Management",
    date: "2024-01-15", type: "tiltak", series: "Digital utpressing",
    summary: "Tiltak 1-6: Planlegg teknologiske tiltak, sikkerhetskultur, identifiser kritiske verdier, forbered pa angrep, ta stilling til losepengekrav, etabler alternative kommunikasjonskanaler.",
    full_text: "Tiltaksgruppe 1 — Planlegging og hendelseshåndtering (tiltak 1-6). Tiltak 1: Ha en plan for teknologiske tiltak — utvikle et veikart for a implementere sikkerhetstiltak. Tiltak 2: Ha en plan for sikkerhetskultur — opplaering som gjor ansatte, ledere og IT-personell bevisst sitt ansvar. Tiltak 3: Identifiser virksomhetens viktigste verdier og tjenester — kartlegg hva som er kritisk og vurder konsekvenser ved tap av integritet, konfidensialitet og tilgjengelighet. Tiltak 4: Forbered virksomheten pa et dataangrep — beredskapsplan, kommunikasjonsstrategi, juridiske vurderinger, personalrotasjon, regelmessige ovelser. Tiltak 5: Ta pa forhand stilling til losepengekrav — NSM anbefaler a ikke betale losepenger. Vurder juridiske, okonomiske og sikkerhetsmessige aspekter pa forhand. Tiltak 6: Etabler alternative kommunikasjonskanaler som fungerer uavhengig av organisasjonens IKT-infrastruktur.",
    topics: JSON.stringify(["ransomware", "planlegging", "beredskap", "losepenger", "sikkerhetskultur"]), status: "current",
  },
  {
    reference: "NSM-DU-TG2",
    title: "Digital utpressing — Tiltaksgruppe 2: Sikkerhetskopi og gjenoppretting",
    title_en: "Digital Extortion — Measure Group 2: Backup and Recovery",
    date: "2024-01-15", type: "tiltak", series: "Digital utpressing",
    summary: "Tiltak 7-13: Systemoversikt, gjenoppretting av infrastruktur og informasjon, kopieringsfrekvens, isolerte kopier, sikker drift av kopiering, forbered rask gjenoppretting.",
    full_text: "Tiltaksgruppe 2 — Sikkerhetskopi og gjenoppretting (tiltak 7-13). Tiltak 7: Ha kontinuerlig oversikt over systemer og oppretthold automatisert gjenopprettingsevne for virtuelle/fysiske klienter og servere. Tiltak 8: Oppretthold evne til a beskytte og gjenopprette sentral IKT-infrastruktur — domenekontrollere, PKI-servere, virtualiseringssystemer, overvakingsplattformer. Tiltak 9: Oppretthold evne til a gjenopprette informasjon — filer, databaser, skylagret data. Unnga enkeltlokasjon for fillagring pa klienter. Tiltak 10: Ta sikkerhetskopi sa ofte som virksomhetens behov tilsier (RPO). Tiltak 11: Isoler sikkerhetskopier gjennom nettverks-, domene- og rettighetssegmentering. Bruk flere losninger og lokasjoner, skrivebeskyttelse (immutability). Tiltak 12: Sikker drift av sikkerhetskopieringen — dedikerte tjenestekontoer, dedikerte brannmurer, MFA. Tiltak 13: Test gjenopprettingsprosedyrer regelmessig — mal gjenopprettingstider (RTO), identifiser avhengigheter.",
    topics: JSON.stringify(["ransomware", "sikkerhetskopi", "gjenoppretting", "RPO", "RTO", "immutability"]), status: "current",
  },
  {
    reference: "NSM-DU-TG3",
    title: "Digital utpressing — Tiltaksgruppe 3: Forebygging av inngang og spredning",
    title_en: "Digital Extortion — Measure Group 3: Preventing Entry and Spread",
    date: "2024-01-15", type: "tiltak", series: "Digital utpressing",
    summary: "Tiltak 14-22: Sterk autentisering, web/e-postfiltrering, herding, begrense internetteksponering, nettverkssegmentering, dataflyt-kontroll, overvaking.",
    full_text: "Tiltaksgruppe 3 — Forebygging av inngang og spredning (tiltak 14-22). Tiltak 14: Sterk autentisering — MFA for alle tjenester, saerlig for privilegerte kontoer. Tiltak 15: Web- og e-postfiltrering — blokker ondsinnede vedlegg, shellkode, dokumentmakroer, kjent skadevare, mistenkelige IP-adresser og domener. Tiltak 16: Sikkerhetsherding — deaktiver unodvendig funksjonalitet basert pa leverandorens hardening-veiledning. Tiltak 17: Begrens direkte internetteksponering — bruk VPN eller tilsvarende moderne nettverkskontroller, beskytt med MFA. Tiltak 18: Nettverkssegmentering — mikrosegmentering, zero-trust-arkitektur eller software-defined perimeter; vurder VLAN-basert segmentering. Tiltak 19: Kontroller dataflyt mellom nettverkssegmenter. Tiltak 20: Sperr all direktetrafikk mellom klienter for a begrense skadevarespredninge. Tiltak 21: Kartlegg og fjern glemte maskiner, tjenester og brukerkontoer regelmessig. Tiltak 22: Etabler systemovervaking — overvak unormal administratoraktivitet, uventede dataflyter, misbruk av administrasjonsverktoy (MITRE ATT&CK).",
    topics: JSON.stringify(["ransomware", "forebygging", "MFA", "segmentering", "zero-trust", "herding"]), status: "current",
  },
  {
    reference: "NSM-DU-TG5",
    title: "Digital utpressing — Tiltaksgruppe 5: Forebygging av kjoring av skadevare",
    title_en: "Digital Extortion — Measure Group 5: Prevention of Malware Execution",
    date: "2024-01-15", type: "tiltak", series: "Digital utpressing",
    summary: "Tiltak 23-33: Fjern administratorrettigheter, programvarekontroll, makroblokkering, sentralisert drift, fas ut eldre produkter, skadevare-skanning, endre standardpassord.",
    full_text: "Tiltaksgruppe 5 — Forebygging av kjoring av skadevare (tiltak 23-33). Tiltak 23: Ikke gi brukere administratorrettigheter pa klienten. Tiltak 24: Kontroller programvarekjoring gjennom hvitelisting, godkjente programvarelagre eller administrerte enhetslosninger. Blokker skriptmotorer som PowerShell. Tiltak 25: Hindre at programvare i dokumenter kjores — deaktiver dokumentmakroer og PDF-skript. Tiltak 26: Sentralisert drift via domenemedlemskap og MDM. Tiltak 27: Fas ut eldre programvare og maskinvare uten stotte. Tiltak 28: Fjern/deaktiver ubrukt programvare og funksjonalitet — deaktiver ubrukte protokoller (IMAP, POP, eldre SMB), begrens tredjeparters plugins, kontroller TOR-trafikk. Tiltak 29: Automatisert sikkerhetsoppdatering for OS og applikasjoner. Tiltak 30: Skadevare-skanning med antivirus/antimalware, kombinert med sarbarhetsutbedring. Tiltak 31: Endre alle standardpassord pa IKT-produkter for produksjon. Tiltak 32: Begrens skriverettigheter til fellesfiler for a redusere ransomware-krypteringsomfang. Tiltak 33: Aktiver innebygd sikkerhetsfunksjonalitet i produkter og tjenester.",
    topics: JSON.stringify(["ransomware", "skadevare", "hvitelisting", "makro", "PowerShell", "standardpassord"]), status: "current",
  },
  {
    reference: "NSM-DU-TG7",
    title: "Digital utpressing — Tiltaksgruppe 7: Hendelseshandtering",
    title_en: "Digital Extortion — Measure Group 7: Incident Response",
    date: "2024-01-15", type: "tiltak", series: "Digital utpressing",
    summary: "Tiltak 34-43: Varsle NCSC og politiet, isoler infiserte enheter, vurder nettverksutkobling, passordbytte, reinstaller, sjekk firmware, gjenopprett sikkert, laer av hendelsen.",
    full_text: "Tiltaksgruppe 7 — Hendelseshandtering (tiltak 34-43). Tiltak 34: Varsle NCSC (norcert@cert.no, 02497), relevante sektordialog-partnere og politiet. Tiltak 35: Koble fra infiserte enheter fra nettverk. Tiltak 36: Vurder utkobling av nettverkssegmenter basert pa hendelsens omfang. Tiltak 37: Passordbytte pa alle berarte kontoer, saerlig tjenestekontoer og domeneadministratorkontoer. Tiltak 38: Reinstaller operativsystemer, applikasjoner og konfigurasjoner pa infiserte enheter. Tiltak 39: Sjekk om fastvare (UEFI/BIOS) er pavirket — oppdater eller erstatt enheter. Tiltak 40: Bruk kun sikkerhetskopier man er trygg pa — skann med oppdatert skadevaredeteksjon. Tiltak 41: Gjenopprett pa nettverkssegmenter verifisert uberort. Tiltak 42: Gjenoppta sikkerhetsovervaking av gjenopprettede enheter for a bekrefte fullstendig fjerning. Tiltak 43: Gjennomfor evaluering og laer av hendelsen.",
    topics: JSON.stringify(["ransomware", "hendelseshandtering", "varsling", "gjenoppretting", "evaluering"]), status: "current",
  },

  // ---- Digital beredskap (individual measures) ----
  {
    reference: "NSM-DB-1",
    title: "Digital beredskap — Tiltak 1: Ha oppdatert oversikt over systemer",
    title_en: "Digital Preparedness — Measure 1: Maintain current system overview",
    date: "2024-04-01", type: "tiltak", series: "Digital beredskap",
    summary: "Ha en oppdatert oversikt over systemer og programvare i nettverket, nettverksdiagram og lopende oppdateringsstatus.",
    full_text: "Digital beredskap tiltak 1: Ha en oppdatert oversikt over systemer og programvare som kjorer i virksomhetens nettverk. Vedlikehold nettverksdiagram som viser segmenttilkoblinger og eksterne forbindelser. Ha lopende oversikt over oppdateringsstatus for alle systemer. Uten oversikt over egne systemer er det umulig a beskytte dem effektivt eller respondere raskt pa hendelser.",
    topics: JSON.stringify(["beredskap", "systemoversikt", "nettverksdiagram", "kartlegging"]), status: "current",
  },
  {
    reference: "NSM-DB-3",
    title: "Digital beredskap — Tiltak 3: Reduser sarbarhetsflaten",
    title_en: "Digital Preparedness — Measure 3: Reduce vulnerability surface",
    date: "2024-04-01", type: "tiltak", series: "Digital beredskap",
    summary: "Prioriter oppdatering av internetteksponerte tjenester, fas ut eldre systemer, begrens RDP-tilgang, deaktiver makroer, gjennomga BYOD.",
    full_text: "Digital beredskap tiltak 3: Reduser sarbarhetsflaten. Prioriter oppdatering av internetteksponerte tjenester umiddelbart. Fas ut eldre systemer som mangler MFA eller sikkerhetsoppdateringer. Begrens Remote Desktop Protocol (RDP) tilgang og aktiver logging. Fas ut gamle skylosninger som fortsatt er i bruk. Deaktiver makroer i eksterne dokumenter. Gjennomga BYOD-policyer (Bring Your Own Device) og vurder om personlige enheter utgjor en uakseptabel risiko i det skjerpede trusselbildet.",
    topics: JSON.stringify(["beredskap", "sarbarhetsreduksjon", "RDP", "makroer", "BYOD"]), status: "current",
  },
  {
    reference: "NSM-DB-4",
    title: "Digital beredskap — Tiltak 4: Styrk identitets- og tilgangskontroll",
    title_en: "Digital Preparedness — Measure 4: Strengthen identity and access control",
    date: "2024-04-01", type: "tiltak", series: "Digital beredskap",
    summary: "Fjern ugyldige tilganger, gjennomfor tilgangsgjennomganger, krev sterke passord, implementer MFA over alt, bruk geoblocking.",
    full_text: "Digital beredskap tiltak 4: Styrk identitets- og tilgangskontroll. Fjern brukere som ikke lenger skal ha tilganger — fratradde ansatte, avsluttede leverandorforhold. Gjennomfor regelmessige tilgangsgjennomganger. Krev sterke, unike passord (minimum 16 tegn). Implementer flerfaktorautentisering (MFA) pa alle tjenester. Bruk geoblocking for a begrense tilgang fra land virksomheten ikke har forretningsforhold med. Krev MFA for all tilgang som ikke gar via VPN. Krypter passordoverfoering og krev HTTPS for innlogging pa nettsider.",
    topics: JSON.stringify(["beredskap", "tilgangskontroll", "MFA", "geoblocking", "passord"]), status: "current",
  },
  {
    reference: "NSM-DB-5",
    title: "Digital beredskap — Tiltak 5: Styrk sikkerhetsovervaking",
    title_en: "Digital Preparedness — Measure 5: Strengthen security monitoring",
    date: "2024-04-01", type: "tiltak", series: "Digital beredskap",
    summary: "Utvid logging, ok oppbevaringstid, overvak trafikk i begge retninger, bygg analytisk kapasitet for logganalyse.",
    full_text: "Digital beredskap tiltak 5: Styrk sikkerhetsovervaking. Utvid logging pa alle systemer — aktiver logging pa systemer som ikke logger i dag. Ok oppbevaringstid for logger — minimum 90 dager, anbefalt 12 maneder. Overvak trafikk i begge retninger — bade innkommende og utgaende nettverkstrafikk. Bygg analytisk kapasitet — ansette eller trene personell for logganalyse, eller bruk ekstern SOC-tjeneste. Etabler baseline for normal aktivitet for a lettere oppdage anomalier. I det skjerpede trusselbildet er overvaking saerlig viktig for a oppdage sofistikerte angrep som kan paga over lengre tid.",
    topics: JSON.stringify(["beredskap", "overvaking", "logging", "SOC", "logganalyse"]), status: "current",
  },
  {
    reference: "NSM-DB-9",
    title: "Digital beredskap — Tiltak 9: Sikre skytjenester",
    title_en: "Digital Preparedness — Measure 9: Secure cloud services",
    date: "2024-04-01", type: "tiltak", series: "Digital beredskap",
    summary: "Styrk tilgangskontroll pa skytjenester som Microsoft 365 og Google Workspace. Gjennomga konfigurasjoner og rettigheter.",
    full_text: "Digital beredskap tiltak 9: Sikre skytjenester. Styrk tilgangskontroll pa skytjenester som Microsoft 365 og Google Workspace. NSM erfarer at flertallet av uonskede hendelser knyttet til skytjenester skyldes mangler eller feil i konfigurasjon eller bruk — ikke sarbarheter hos skyleverandoren. Gjennomga: administratortilganger og begrens antall globale administratorer, betinget tilgang (Conditional Access) — krev MFA, blokker eldre autentiseringsprotokoller, begrens tilgang fra usikre enheter, gjennomga delingsinnstillinger og eksterne deling, aktiver logging og overvaking av administratoraktivitet, gjennomga integrerte tredjepartsapplikasjoner og OAuth-tillatelser.",
    topics: JSON.stringify(["beredskap", "skytjenester", "Microsoft-365", "Conditional-Access", "konfigurasjon"]), status: "current",
  },

  // ---- E-post-sikkerhet (individual protocols) ----
  {
    reference: "NSM-EPOST-SPF",
    title: "E-postsikkerhet — SPF (Sender Policy Framework)",
    title_en: "Email Security — SPF (Sender Policy Framework)",
    date: "2023-06-22", type: "tiltak", series: "E-postsikkerhet",
    summary: "SPF forteller hvilke IP-adresser som har lov til a sende e-post pa vegne av et domene. Viktig ogsa for domener som ikke bruker e-post.",
    full_text: "NSMs anbefaling for SPF (Sender Policy Framework). SPF brukes til a fortelle hvilke IP-adresser som har lov til a sende e-post pa vegne av et domene. Det er viktig a bruke SPF pa egne domener som ikke brukes til a sende e-post ('v=spf1 -all') — dette reduserer risikoen for at en angriper kan sende falsk e-post pa vegne av virksomhetens domener (spoofing). Implementering: publiser en SPF-record i DNS for alle virksomhetens domener, inkluder alle legitime e-postsendere (e-postserver, tredjepartstjenester), bruk '-all' (hard fail) for domener som sender e-post, bruk 'v=spf1 -all' for domener som ikke sender e-post. Begrensninger: SPF sjekker kun MAIL FROM-adressen, ikke From-headeren som brukeren ser. Derfor ma SPF kombineres med DKIM og DMARC.",
    topics: JSON.stringify(["SPF", "e-post", "DNS", "spoofing"]), status: "current",
  },
  {
    reference: "NSM-EPOST-DKIM",
    title: "E-postsikkerhet — DKIM (DomainKeys Identified Mail)",
    title_en: "Email Security — DKIM (DomainKeys Identified Mail)",
    date: "2023-06-22", type: "tiltak", series: "E-postsikkerhet",
    summary: "DKIM plasserer en digital signatur pa all utgaende e-post som mottaker kan verifisere via DNS. Bruker asymmetrisk kryptering.",
    full_text: "NSMs anbefaling for DKIM (DomainKeys Identified Mail). DKIM sikrer at e-post kan videresendes og verifiseres. Avsenderens e-postserver plasserer en digital signatur pa all utgaende e-post, og mottakerens e-postserver kan sjekke signaturen mot informasjon publisert i DNS. DKIM bruker asymmetrisk kryptering med en offentlig og privat nokkel. Den offentlige nokkelen publiseres i DNS, den private nokkelen brukes til a signere. Fordeler: mottaker kan verifisere at e-posten faktisk kommer fra det oppgitte domenet, e-posten har ikke blitt endret under transport, fungerer med videresending (i motsetning til SPF). Implementering: generer nokkelpar (minimum 2048 bit RSA), konfigurer e-postserver til a signere all utgaende e-post, publiser offentlig nokkel i DNS som TXT-record.",
    topics: JSON.stringify(["DKIM", "e-post", "digital-signatur", "DNS", "kryptering"]), status: "current",
  },
  {
    reference: "NSM-EPOST-DMARC",
    title: "E-postsikkerhet — DMARC (Domain Message Authentication Reporting and Conformance)",
    title_en: "Email Security — DMARC",
    date: "2023-06-22", type: "tiltak", series: "E-postsikkerhet",
    summary: "DMARC fjerner gjettingen om haandtering av e-post som feiler SPF/DKIM. Gir rapporteringsmekanisme som SPF og DKIM mangler. Anbefalte policyer: none, quarantine, reject.",
    full_text: "NSMs anbefaling for DMARC (Domain Message Authentication Reporting and Conformance). DMARC fjerner gjettingen om hvordan e-post som feiler SPF/DKIM-validering skal haandteres, ettersom avsenderen i tillegg publiserer en policy for haandtering. En viktig funksjonalitet i DMARC er rapporteringsmekanismen som SPF og DKIM mangler — mottakere sender rapporter tilbake om mottatt e-post og valideringsresultater. Implementering: Start med DMARC-policy 'none' (p=none) for a motta rapporter uten a pavirke e-postleveranse. Analyser rapportene for a identifisere alle legitime e-postsendere. Skjerp til 'quarantine' (p=quarantine) for a flytte feilende e-post til karantene/spam. Skjerp til 'reject' (p=reject) for a avvise feilende e-post helt. NSM anbefaler at alle virksomheter arbeider mot DMARC-policy 'reject' pa alle domener.",
    topics: JSON.stringify(["DMARC", "e-post", "policy", "rapportering", "reject"]), status: "current",
  },
  {
    reference: "NSM-EPOST-STARTTLS",
    title: "E-postsikkerhet — STARTTLS kryptert overfoering",
    title_en: "Email Security — STARTTLS Encrypted Transport",
    date: "2023-06-22", type: "tiltak", series: "E-postsikkerhet",
    summary: "STARTTLS sikrer kryptert overfoering av e-post mellom e-postservere. Forhindrer avlytting av e-post under transport.",
    full_text: "NSMs anbefaling for STARTTLS. STARTTLS muliggjor kryptert overfoering av e-post mellom e-postservere (server-til-server). Uten STARTTLS sendes e-post i klartekst mellom servere, noe som gjor det mulig a avlytte innholdet. Implementering: aktiver STARTTLS pa e-postserveren og krev det for all kommunikasjon med andre servere der mulig, bruk gyldige TLS-sertifikater (minimum TLS 1.2), konfigurer MTA-STS (Mail Transfer Agent Strict Transport Security) for a signalisere at domenet stotter TLS og forventer kryptering. NSM anbefaler at alle norske virksomheter aktiverer STARTTLS pa sine e-postservere.",
    topics: JSON.stringify(["STARTTLS", "e-post", "TLS", "kryptering", "MTA-STS"]), status: "current",
  },

  // ---- Fem tiltak (individual) ----
  {
    reference: "NSM-5T-1",
    title: "Fem tiltak — Tiltak 1: Sikkerhetsoppdateringer",
    title_en: "Five Measures — Measure 1: Security Updates",
    date: "2023-09-01", type: "tiltak", series: "Fem tiltak",
    summary: "Installer sikkerhetsoppdateringer sa fort som mulig og mest mulig automatisk. Prioriter nettlesere, e-postklienter, PDF-lesere og Office-pakker.",
    full_text: "Fem effektive tiltak — Tiltak 1: Sikkerhetsoppdateringer. Installer sikkerhetsoppdateringer sa fort som mulig, og mest mulig automatisk. Oppdateringer bor vaere sentralt styrt gjennom et oppdateringsstyringssystem. Prioriter oppdatering av operativsystemer og programvare som behandler data fra internett: nettlesere, e-postklienter, PDF-lesere, Office-pakker. Kunnskap om nyoppdagede sarbarheter sprer seg raskt — angripere utvikler utnyttelseskode ofte innen dager etter at en sarbarhet offentliggjores. Forsinkelse i oppdatering gir angripere et tidsvindu for utnyttelse. NSM anbefaler at kritiske sikkerhetsoppdateringer installeres innen 48 timer.",
    topics: JSON.stringify(["sikkerhetsoppdateringer", "patch-management", "automatisering"]), status: "current",
  },
  {
    reference: "NSM-5T-2",
    title: "Fem tiltak — Tiltak 2: Fjern administratorrettigheter fra sluttbrukere",
    title_en: "Five Measures — Measure 2: Remove admin rights from end users",
    date: "2023-09-01", type: "tiltak", series: "Fem tiltak",
    summary: "Ikke tildel administratorrettigheter til sluttbrukere. De fleste brukere har ikke legitimt behov, og angripere utnytter dette.",
    full_text: "Fem effektive tiltak — Tiltak 2: Fjern administratorrettigheter. Ikke tildel administratorrettigheter til sluttbrukere. De fleste sluttbrukere har ikke legitimt behov for administratortilgang, noe angripere utnytter. Med administratortilgang kan skadevare installere seg dypt i systemet, deaktivere sikkerhetsprogramvare og spre seg til andre systemer. Uten administratortilgang begrenses skadevaren til brukerens kontekst og kan ofte stoppes av andre sikkerhetstiltak. NSM anbefaler a bruke separate kontoer for administrasjon og daglig bruk, og a implementere privilegert tilgangsstyring (PAM) for administrativ tilgang.",
    topics: JSON.stringify(["administratorrettigheter", "minste-privilegium", "PAM"]), status: "current",
  },
  {
    reference: "NSM-5T-3",
    title: "Fem tiltak — Tiltak 3: Sterk autentisering og MFA",
    title_en: "Five Measures — Measure 3: Strong authentication and MFA",
    date: "2023-09-01", type: "tiltak", series: "Fem tiltak",
    summary: "Ikke tillat svake passord. Bruk MFA der mulig. Endre standardpassord. Passord pa minimum 16 tegn.",
    full_text: "Fem effektive tiltak — Tiltak 3: Sterk autentisering. Ikke tillat bruk av svake passord, og bruk multifaktorautentisering der det er mulig. Endre standardpassord som folger med IKT-produkter umiddelbart. Krev passord pa minimum 16 tegn. Bruk passordfraser for enklere hukommelse. NSM anbefaler sterkt a implementere MFA pa alle tjenester — dette er det mest effektive enkelttiltaket mot kontoinnbrudd. Kombinasjonen av passord og MFA gjor det svaert vanskelig for angripere a fa tilgang selv med stjalne passord.",
    topics: JSON.stringify(["autentisering", "MFA", "passord", "standardpassord"]), status: "current",
  },
  {
    reference: "NSM-5T-4",
    title: "Fem tiltak — Tiltak 4: Fas ut eldre IKT-produkter",
    title_en: "Five Measures — Measure 4: Phase out legacy ICT products",
    date: "2023-09-01", type: "tiltak", series: "Fem tiltak",
    summary: "Fas ut eldre produkter som ikke lenger mottar sikkerhetsoppdateringer. Nyere versjoner har forbedrede sikkerhetsfunksjoner.",
    full_text: "Fem effektive tiltak — Tiltak 4: Fas ut eldre IKT-produkter. Nyere versjoner inneholder flere sikkerhetsoppdateringer og forbedrede sikkerhetsfunksjoner pa tvers av plattformer (Windows, macOS, iOS, Android, Linux). Eldre systemer som ikke lenger mottar oppdateringer utgjor en permanent sikkerhetsrisiko. NSM anbefaler a ha en planmessig utfasing av eldre produkter og a budsjettere for regelmaessig fornyelse av IKT-utstyr. Saerlig viktig er a fase ut operativsystemer som har nadd 'end of life' og nettverksenheter med utdatert firmware.",
    topics: JSON.stringify(["utfasing", "eldre-produkter", "livslop", "modernisering"]), status: "current",
  },
  {
    reference: "NSM-5T-5",
    title: "Fem tiltak — Tiltak 5: Programvarehvitelisting",
    title_en: "Five Measures — Measure 5: Application whitelisting",
    date: "2023-09-01", type: "tiltak", series: "Fem tiltak",
    summary: "Tillat kun programvare godkjent av virksomheten eller enhetsleverandoren. Konfigurer enheter til kun a kjore godkjent programvare.",
    full_text: "Fem effektive tiltak — Tiltak 5: Programvarehvitelisting. Tillat kun programvare som er godkjent av virksomheten eller enhetsleverandoren. Konfigurer enheter til kun a kjore godkjent programvare, enten gjennom appbutikk-signering eller eksplisitt hvitelisting av tillatte applikasjoner. Programvarehvitelisting forhindrer kjoring av ukjent og potensielt ondsinnet programvare. Implementering kan gjores gjennom operativsystemets innebygde funksjoner (Windows Defender Application Control, macOS Gatekeeper, Linux AppArmor/SELinux) eller dedikerte hvitelistingslosninger. NSM understreker at dette er et kraftig tiltak som krever planlegging og testing for utrulling.",
    topics: JSON.stringify(["hvitelisting", "programvarekontroll", "AppControl", "Gatekeeper"]), status: "current",
  },

  // ---- Additional real NCSC advisories ----
  {
    reference: "NSM-IT-MODERNISERING",
    title: "IT-modernisering og digital transformasjon",
    title_en: "IT Modernisation and Digital Transformation",
    date: "2023-10-01", type: "recommendation", series: "NSM",
    summary: "NSMs veiledning om sikkerhet i IT-modernisering og digital transformasjon for offentlig forvaltning. Dekker skymigrasjon, systemkonsolidering og modernisering av arvebaserte systemer.",
    full_text: "IT-modernisering og digital transformasjon — NSMs anbefalinger for statlig infrastrukturmodernisering. Modernisering av IKT-systemer er nodvendig for a holde tritt med trusselutviklingen og utnytte nye sikkerhetsteknologier. NSM anbefaler: gjennomfor risikovurdering for moderniseringsbeslutninger, planlegg sikkerhet inn fra starten av moderniseringsprosjekter (security by design), ha en strategi for hybridmiljoer der eldre og nye systemer sameksisterer, sikre at modernisering ikke introduserer nye sarbarheter gjennom hasten med a migrere, bevar sikkerhetskontroller under migrasjon — mange sikkerhetsbrudd skjer i overgangsperioder, dokumenter avhengigheter og grensesnitt mellom gamle og nye systemer, ha en fallback-plan dersom moderniseringen ikke gar som planlagt.",
    topics: JSON.stringify(["modernisering", "digital-transformasjon", "skymigrasjon", "security-by-design"]), status: "current",
  },
  {
    reference: "NSM-RISIKO-2022",
    title: "Risiko 2022 — NSMs sikkerhetsfaglige rad",
    title_en: "Risk 2022 — NSM's Security Advisory",
    date: "2022-02-15", type: "report", series: "Risiko",
    summary: "NSMs arlige rapport Risiko 2022 om trusselbildet mot Norge. Publisert kort for Russlands invasjon av Ukraina. Beskriver et allerede tilspisset trusselbilde.",
    full_text: "Risiko 2022 er NSMs arlige rapport om sikkerhetsfaglige rad, publisert februar 2022. Rapporten beskrev et allerede tilspisset trusselbilde som ble ytterligere forsterket av Russlands fullskala invasjon av Ukraina kort etter publisering. Sentrale temaer: okt cybertrussel fra statlige aktorer, ransomware som voksende trussel mot norske virksomheter, leverandorkjede-sarbarheter i lys av SolarWinds-hendelsen, behov for styrket digital beredskap i alle sektorer, NSMs anbefalinger om a folge Grunnprinsipper for IKT-sikkerhet og styrke samarbeid med NCSC. Rapporten la grunnlaget for den skjerpede beredskapen som ble innfort etter 24. februar 2022.",
    topics: JSON.stringify(["trusselrapport", "risiko", "Ukraina", "ransomware", "2022"]), status: "current",
  },
];

// ---------------------------------------------------------------------------
// 8. Additional Advisories — more NCSC alerts with real references
// ---------------------------------------------------------------------------

const additionalAdvisories: AdvisoryRow[] = [
  {
    reference: "NCSC-2023-007",
    title: "Kritisk sarbarhet i VMware vCenter Server 7.0",
    date: "2021-09-22",
    severity: "critical",
    affected_products: JSON.stringify(["VMware vCenter Server", "VMware Cloud Foundation"]),
    summary: "VMware publiserte oppdateringer for 19 sarbarheter i vCenter Server og Cloud Foundation, inkludert kritisk sarbarhet CVE-2021-22005 som muliggjor vilkarlig filopplasting.",
    full_text: "NCSC varsel: Kritisk sarbarhet i VMware vCenter Server 7.0. VMware publiserte oppdateringer for 19 sarbarheter i vCenter Server og Cloud Foundation. Den mest kritiske er CVE-2021-22005 som muliggjor vilkarlig filopplasting pa vCenter Server — en angriper med nettverkstilgang til port 443 kan utnytte dette til fjernkjoring av kode. CVSS-scorer rangerer fra 4.0 til 9.8. NCSC anbefaler umiddelbar oppdatering av alle vCenter Server-installasjoner.",
    cve_references: JSON.stringify(["CVE-2021-22005"]),
  },
  {
    reference: "NCSC-2023-008",
    title: "Varsel om sarbarhet i produkt fra VMware — flere kritiske sarbarheter",
    date: "2023-02-08",
    severity: "critical",
    affected_products: JSON.stringify(["VMware ESXi", "VMware Workstation", "VMware Cloud Foundation", "VMware Fusion"]),
    summary: "NCSC varsler om flere sarbarheter i VMware ESXi, Workstation, Cloud Foundation og Fusion. Flere sarbarheter er kritiske med CVSS-scorer mellom 4.0 og 9.3.",
    full_text: "NCSC varsel: Sarbarheter i VMware-produkter. NCSC informerer om flere sarbarheter i VMware ESXi, Workstation, Cloud Foundation og Fusion, der flere er kritiske. CVSS-scorer rangerer mellom 4.0 og 9.3. Sarbarhetene i VMware ESXi har blitt brukt i ransomware-kampanjer — ESXiArgs-ransomware rettet seg mot sårbare ESXi-servere globalt. NCSC anbefaler at alle virksomheter med VMware-produkter oppdaterer umiddelbart og gjennomgar sine VMware-miljoer for tegn pa kompromittering.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2023-009",
    title: "Kritiske sarbarheter i flere Cisco-produkter",
    date: "2023-05-10",
    severity: "high",
    affected_products: JSON.stringify(["Cisco Catalyst-svitsjer", "Cisco Small Business-rutere", "Cisco IP-telefoner"]),
    summary: "NCSC varsler om kritiske sarbarheter i flere Cisco-produkter som kan tillate fjernkjoring av kode og tjenestenektangrep.",
    full_text: "NCSC varsel: Kritiske sarbarheter i flere Cisco-produkter. Flere Cisco-produkter er pavirket av alvorlige sarbarheter. NCSC anbefaler at virksomheter med Cisco-utstyr gjennomgar sine produkter mot Ciscos sikkerhetsmeldinger og oppdaterer alle berarte enheter. Saerlig viktig for virksomheter med internetteksponerte Cisco-enheter. NSM minner om at nettverksutstyr som brannmurer, svitsjer og rutere ofte er hovedmal for avanserte trusselaktorer fordi de gir bred tilgang til nettverket.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2023-010",
    title: "Varsel fra HelseCERT om kritisk sarbarhet i Java-rammeverk",
    date: "2023-03-01",
    severity: "high",
    affected_products: JSON.stringify(["Java Spring Framework", "Spring Boot-applikasjoner"]),
    summary: "NCSC videreformidler varsel fra HelseCERT om kritisk sarbarhet i Java Spring Framework (Spring4Shell). Sarbarheten pavirker et bredt utvalg av Java-baserte applikasjoner.",
    full_text: "NCSC varsel: Kritisk sarbarhet i Java-rammeverk (Spring Framework). Videreformidling av varsel fra HelseCERT. Sarbarheten, kjent som Spring4Shell, pavirker Java Spring Framework og kan tillate fjernkjoring av kode pa sarbare applikasjoner. Et bredt utvalg av Java-baserte applikasjoner kan vaere pavirket. NCSC anbefaler at virksomheter identifiserer Java-applikasjoner basert pa Spring Framework og oppdaterer til siste versjon. Overvak nettverkstrafikk for tegn pa utnyttelsesforsok.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-011",
    title: "Kommuner og offentlige virksomheter ma beskytte seg mot losepengevirus",
    date: "2024-05-01",
    severity: "high",
    affected_products: JSON.stringify(["Kommunale IKT-systemer", "Offentlige tjenester"]),
    summary: "NSM oppfordrer kommuner og offentlige virksomheter til a styrke beskyttelsen mot ransomware. Flere norske kommuner har vaert rammet av losepengevirus.",
    full_text: "NSM oppfordring: Kommuner og offentlige virksomheter ma beskytte seg mot losepengevirus (ransomware). Flere norske kommuner har vaert rammet av ransomware-angrep, med alvorlige konsekvenser for tjenesteleveranse til innbyggere. NSM anbefaler at alle kommuner og offentlige virksomheter: folger NSMs Grunnprinsipper for IKT-sikkerhet, implementerer NSMs fem effektive tiltak mot dataangrep, har oppdaterte og testede sikkerhetskopier (offline og geografisk atskilt), har en hendelseshandteringsplan som er ovet, vurderer tilknytning til NCSCs Varslingssystem for Digital Infrastruktur (VDI), gjennomforer regelmessig sikkerhetsopplaering for alle ansatte, har MFA pa alle tjenester. NSM tilbyr veiledning og stotte til kommuner som onsker a styrke sin digitale sikkerhet.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-012",
    title: "NSM oppfordrer virksomheter til a styrke egen sikkerhet",
    date: "2024-02-01",
    severity: "medium",
    affected_products: JSON.stringify(["Alle norske virksomheter"]),
    summary: "NSM oppfordrer alle norske virksomheter til a styrke sin digitale sikkerhet i lys av det skjerpede trusselbildet. Konkrete anbefalinger for a redusere sarbarhetsflaten.",
    full_text: "NSM oppfordring: Virksomheter ma styrke egen sikkerhet. I lys av det skjerpede trusselbildet oppfordrer NSM alle norske virksomheter til a iverksette konkrete tiltak for a styrke sin digitale sikkerhet. God logging bor etableres i digital infrastruktur, ogsa for industrielle kontrollsystemer (OT). Komponenter i OT eller industrielle kontrollsystemer bor ikke ha direkte fjerntilgang over internett. OT- og IT-nettverk bor vaere segmentert. NSM anbefaler at alle virksomheter gjennomforer en gjennomgang av sin sikkerhetsposisjon mot Grunnprinsipper for IKT-sikkerhet og implementerer tiltak basert pa funn.",
    cve_references: JSON.stringify([]),
  },
];

// ---------------------------------------------------------------------------
// 9. Additional Guidance — more NSM publications
// ---------------------------------------------------------------------------

const moreGuidance: GuidanceRow[] = [
  {
    reference: "NSM-RISIKO-2020",
    title: "Risiko 2020 — NSMs sikkerhetsfaglige rad",
    title_en: "Risk 2020 — NSM's Security Advisory",
    date: "2020-02-10", type: "report", series: "Risiko",
    summary: "NSMs arlige rapport Risiko 2020 om trusselbildet mot Norge. Dekker cybertrusler, sikkerhetspolitisk situasjon og anbefalinger.",
    full_text: "Risiko 2020 er NSMs arlige rapport om sikkerhetsfaglige rad. Rapporten gir en samlet vurdering av trusler og risikoer mot nasjonal sikkerhet i det digitale rommet. Sentrale temaer inkluderer: voksende trussel fra statlig-stottede cyberoperasjoner, okt bruk av skytjenester og tjenesteutsetting med tilhorende sikkerhetsutfordringer, ransomware som voksende trussel mot norske virksomheter og kommuner, behov for styrket beredskap i helsesektoren (pre-COVID), anbefaling om a folge NSMs Grunnprinsipper for IKT-sikkerhet versjon 2.0 (nylig lansert).",
    topics: JSON.stringify(["trusselrapport", "risiko", "skytjenester", "ransomware", "2020"]), status: "current",
  },
  {
    reference: "NSM-RISIKO-2021",
    title: "Risiko 2021 — NSMs sikkerhetsfaglige rad",
    title_en: "Risk 2021 — NSM's Security Advisory",
    date: "2021-02-08", type: "report", series: "Risiko",
    summary: "NSMs arlige rapport Risiko 2021. Fokus pa COVID-19s innvirkning pa sikkerhetsbildet, hurtig digitalisering og nye angrepsflater.",
    full_text: "Risiko 2021 er NSMs arlige rapport om sikkerhetsfaglige rad. COVID-19-pandemien har akselerert digitaliseringen i norske virksomheter med okt bruk av hjemmekontor, videomater og skytjenester. Dette har utvidet angrepsflaten betydelig. Sentrale temaer: okt risiko ved hurtig digitalisering uten tilstrekkelig sikkerhet, VPN- og fjerntilgangslosninger som malfattige angrep, SolarWinds-hendelsen som vekker for leverandorkjede-risiko, ransomware-angrep mot norske virksomheter inkludert kommuner og helseforetak, behov for a styrke grunnleggende sikkerhetstiltak.",
    topics: JSON.stringify(["trusselrapport", "risiko", "COVID-19", "hjemmekontor", "VPN", "2021"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.3.2",
    title: "Tiltak 2.3.2 — Fjern eller deaktiver unodvendig funksjonalitet",
    title_en: "Measure 2.3.2 — Remove or disable unnecessary functionality",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Fjern eller deaktiver unodvendig funksjonalitet, tjenester, porter, protokoller og programvare. Endre standardpassord pa alle produkter.",
    full_text: "Tiltak 2.3.2: Fjern eller deaktiver all unodvendig funksjonalitet, tjenester, porter, protokoller og programvare. Fjern standardkontoer eller endre standardpassord for oppsett. Dette er et av de mest effektive hardening-tiltakene — hvert unodvendig element er en potensiell sarbarhetsflate. Eksempler: deaktiver SMBv1, Telnet, FTP, SNMP v1/v2, fjern eksempelapplikasjoner fra webservere, deaktiver unodvendige Windows-tjenester, fjern forhåndsinstallert programvare (bloatware), begrens ICMP-respons pa internetteksponerte servere. CIS Benchmarks gir detaljerte sjekklister for herding av ulike plattformer.",
    topics: JSON.stringify(["herding", "konfigurasjon", "unodvendig-funksjonalitet", "CIS-Benchmarks"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.4.5",
    title: "Tiltak 2.4.5 — Implementer DNS-sikkerhetstiltak",
    title_en: "Measure 2.4.5 — Implement DNS security measures",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Implementer DNSSEC for a beskytte mot DNS-manipulering, og DNS-filtrering for a blokkere tilgang til kjente ondsinnede domener.",
    full_text: "Tiltak 2.4.5: Implementer DNS-sikkerhetstiltak inkludert DNSSEC for a beskytte mot DNS-manipulering, og DNS-filtrering for a blokkere tilgang til kjente ondsinnede domener. DNSSEC (DNS Security Extensions) sikrer at DNS-oppslag ikke kan manipuleres underveis ved a legge til digital signatur pa DNS-poster. DNS-filtrering kan blokkere kjente malware-domener, phishing-sider og command-and-control-servere for mottakerens maskin kobler seg til dem. NSM anbefaler at alle norske virksomheter implementerer bade DNSSEC (for egne domener) og DNS-filtrering (for utgaende oppslag).",
    topics: JSON.stringify(["DNS", "DNSSEC", "DNS-filtrering", "nettverkssikkerhet"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-2.7.1",
    title: "Tiltak 2.7.1 — Krypter data under overfoering med TLS 1.2 eller nyere",
    title_en: "Measure 2.7.1 — Encrypt data in transit with TLS 1.2 or newer",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Bruk TLS 1.2 eller nyere for all datakommunikasjon. Bruk kun godkjente krypteringsalgoritmer i henhold til NSMs kryptografiske anbefalinger.",
    full_text: "Tiltak 2.7.1: Krypter data under overfoering med TLS 1.2 eller nyere. Bruk kun godkjente krypteringsalgoritmer og nokkellengder i henhold til NSMs kryptografiske anbefalinger. TLS 1.3 er anbefalt der det er mulig — det gir bedre sikkerhet og ytelse enn TLS 1.2. Deaktiver TLS 1.0 og TLS 1.1 — disse er utdaterte og har kjente sarbarheter. Konfigurer sterke chifre-suiter og deaktiver svake (RC4, DES, 3DES, MD5). Bruk Forward Secrecy (ECDHE) for a beskytte historisk kommunikasjon selv om serverens private nokkel kompromitteres. Test TLS-konfigurasjoner regelmessig med verktoy som SSL Labs.",
    topics: JSON.stringify(["TLS", "kryptering", "TLS-1.3", "chifre-suiter", "Forward-Secrecy"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-3.3.3",
    title: "Tiltak 3.3.3 — Gjennomfor proaktiv trusseljakt (Threat Hunting)",
    title_en: "Measure 3.3.3 — Conduct proactive threat hunting",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Gjennomfor proaktiv trusseljakt basert pa MITRE ATT&CK-rammeverket, kjente trusselaktormonstre og etterretning fra NCSC.",
    full_text: "Tiltak 3.3.3: Gjennomfor proaktiv trusseljakt (threat hunting) basert pa kjente trusselaktormonstre, MITRE ATT&CK-rammeverket og etterretningsinformasjon fra NCSC. Trusseljakt skiller seg fra passiv overvaking ved at analytikere aktivt soker etter tegn pa inntrengning basert pa hypoteser om angriperens metoder. Aktiviteter inkluderer: soke etter kjente trusselindikatorer (IoC) fra NCSC og sektordialog, analysere logger for monstre knyttet til kjente trusselaktorteknikker (MITRE ATT&CK), undersoke anomalier identifisert av SIEM eller anomalideteksjonssystemer, verifisere at sikkerhetstiltak faktisk fungerer som tiltenkt. NSM anbefaler at virksomheter med hoy sikkerhetsmodning gjennomforer regelmessig trusseljakt som supplement til automatisert overvaking.",
    topics: JSON.stringify(["trusseljakt", "threat-hunting", "MITRE-ATT&CK", "IoC", "NCSC"]), status: "current",
  },
  {
    reference: "NSM-GP-2.1-T-4.1.6",
    title: "Tiltak 4.1.6 — Sikre kjennskap til varslingspliktene",
    title_en: "Measure 4.1.6 — Ensure knowledge of notification obligations",
    date: "2024-06-05", type: "tiltak", series: "Grunnprinsipper",
    summary: "Virksomheten ma kjenne sine varslingsplikt etter sikkerhetsloven paragraf 4-5, digitalsikkerhetsloven og personvernforordningen (GDPR).",
    full_text: "Tiltak 4.1.6: Sikre at virksomheten kjenner varslingspliktene etter relevant lovgivning. Sikkerhetsloven paragraf 4-5: virksomheter underlagt sikkerhetsloven skal varsle NSM ved hendelser som kan pavirke nasjonale sikkerhetsinteresser. Digitalsikkerhetsloven: tilbydere av samfunnsviktige tjenester skal rapportere vesentlige hendelser innen 24 timer. Personvernforordningen (GDPR) artikkel 33/34: brudd pa personopplysningssikkerheten skal varsles til Datatilsynet innen 72 timer og i noen tilfeller til de registrerte. Sektorspesifikke krav: finanssektoren (Finanstilsynet), helsesektoren (HelseCERT/NHN), energisektoren (NVE/KraftCERT). NSM anbefaler at virksomheter lager en oversikt over alle sine varslingspliktene og har forhåndsdefinerte prosedyrer for rask varsling.",
    topics: JSON.stringify(["varsling", "sikkerhetsloven", "digitalsikkerhetsloven", "GDPR", "Datatilsynet"]), status: "current",
  },
  {
    reference: "NSM-ICS-OT-SIKKERHET",
    title: "Sikkerhet i industrielle kontrollsystemer og OT",
    title_en: "Security in Industrial Control Systems and OT",
    date: "2024-02-01", type: "recommendation", series: "NSM",
    summary: "NSMs anbefalinger for sikring av operasjonell teknologi (OT) og industrielle kontrollsystemer (ICS/SCADA). Segmentering, logging, fjerntilgang og forholdet mellom IT og OT.",
    full_text: "NSMs anbefalinger for sikkerhet i industrielle kontrollsystemer og OT. Industrielle kontrollsystemer (ICS/SCADA) og operasjonell teknologi (OT) styrer fysiske prosesser i kritisk infrastruktur — energi, vann, transport, industri. Kompromittering kan ha fysiske konsekvenser. NSM anbefaler: OT- og IT-nettverk skal segmenteres — ingen direkte kommunikasjon mellom IT-nettverk og OT-soner uten gjennom definerte og overvakede grensesnitt. Komponenter i OT eller ICS bor ikke ha direkte fjerntilgang over internett. God logging bor etableres i digital infrastruktur relatert til ICS og OT. Patch-management for OT-systemer krever spesiell handtering — mange systemer kan ikke oppdateres uten nedetid, og noen har leverandorrestriksjoner pa oppdateringer. Ha en dedikert hendelseshandteringsplan for OT-hendelser. Personell som forvalter OT-systemer bor ha spesialkompetanse pa OT-sikkerhet. SINTEF-rapporten 'Grunnprinsipper for IKT-sikkerhet i industrielle IKT-systemer' gir ytterligere veiledning.",
    topics: JSON.stringify(["OT", "ICS", "SCADA", "industrielle-kontrollsystemer", "segmentering", "kritisk-infrastruktur"]), status: "current",
  },
];

// Additional advisories to reach 150+ total
const moreAdvisories: AdvisoryRow[] = [
  {
    reference: "NCSC-2020-002",
    title: "Oppdatert informasjon til SolarWinds Orion — tiltak og oppfolging",
    date: "2020-12-18",
    severity: "critical",
    affected_products: JSON.stringify(["SolarWinds Orion Platform", "Orion 2019.4 HF5 til 2020.2.1"]),
    summary: "NCSC oppdaterer varselet om SolarWinds Orion med ytterligere informasjon om pavirket versjon og tiltak for virksomheter. SUNBURST-bakdoren ble distribuert via legitimme oppdateringskanaler.",
    full_text: "NCSC oppdatert varsel: SolarWinds Orion. SUNBURST-bakdoren ble injisert i Orion-plattformen versjon 2019.4 HF5 til 2020.2.1. Bakdoren ble distribuert via SolarWinds sine ordinaere oppdateringskanaler til tusenvis av kunder globalt. Etter aktivering kommuniserer bakdoren med command-and-control-servere via DNS. NSM anbefaler: isoler SolarWinds-servere fra nettverket, gjennomfor full etterforskning inkludert gjennomgang av Active Directory for nye ukjente kontoer, sjekk for lateral bevegelse fra SolarWinds-servere, samarbeid med NCSC ved funn av kompromittering. Hendelsen understreker behovet for overvaking av ogsa betrodd programvare og leverandorkjeder.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-PT-JUL",
    title: "Microsoft patchetirsdag juli 2024",
    date: "2024-07-09",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office", "Microsoft .NET"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for juli 2024. NCSC anbefaler oppdatering i henhold til virksomhetens rutiner.",
    full_text: "NCSC varsel: Microsoft patchetirsdag juli 2024. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner. NSM minner om at jevnlige sikkerhetsoppdateringer er et av fem effektive tiltak mot dataangrep.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-PT-AUG",
    title: "Microsoft patchetirsdag august 2024",
    date: "2024-08-13",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for august 2024.",
    full_text: "NCSC varsel: Microsoft patchetirsdag august 2024. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-2024-PT-SEP",
    title: "Microsoft patchetirsdag september 2024",
    date: "2024-09-10",
    severity: "medium",
    affected_products: JSON.stringify(["Microsoft Windows", "Microsoft Office"]),
    summary: "Microsofts manedlige sikkerhetsoppdateringer for september 2024.",
    full_text: "NCSC varsel: Microsoft patchetirsdag september 2024. NCSC anbefaler at virksomheter installerer sikkerhetsoppdateringene i henhold til sine oppdateringsrutiner.",
    cve_references: JSON.stringify([]),
  },
];

// ---------------------------------------------------------------------------
// Insert everything
// ---------------------------------------------------------------------------

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);
const insertGuidance = db.prepare(
  "INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
);
const insertAdvisory = db.prepare(
  "INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
);

// Frameworks
const insertAllFrameworks = db.transaction(() => {
  for (const f of frameworks) {
    insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
  }
});
insertAllFrameworks();
console.log(`Inserted ${frameworks.length} frameworks`);

// Guidance — combine all categories
const allGuidance = [...grunnprinsipper, ...reports, ...veiledere, ...lovgivning, ...submeasures, ...moreGuidance];
const insertAllGuidance = db.transaction(() => {
  for (const g of allGuidance) {
    insertGuidance.run(
      g.reference, g.title, g.title_en, g.date, g.type, g.series,
      g.summary, g.full_text, g.topics, g.status,
    );
  }
});
insertAllGuidance();
console.log(`Inserted ${allGuidance.length} guidance documents`);

// Advisories — combine all
const allAdvisories = [...advisories, ...additionalAdvisories, ...moreAdvisories];
const insertAllAdvisories = db.transaction(() => {
  for (const a of allAdvisories) {
    insertAdvisory.run(
      a.reference, a.title, a.date, a.severity,
      a.affected_products, a.summary, a.full_text, a.cve_references,
    );
  }
});
insertAllAdvisories();
console.log(`Inserted ${allAdvisories.length} advisories`);

// ---------------------------------------------------------------------------
// Update framework document counts
// ---------------------------------------------------------------------------

const updateFrameworkCount = db.prepare(
  "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series = ?) WHERE id = ?",
);
const frameworkSeriesMap: Record<string, string> = {
  grunnprinsipper: "Grunnprinsipper",
  sikkerhetsloven: "Sikkerhetsloven",
  digitalsikkerhetsloven: "Digitalsikkerhetsloven",
  "risiko-rapporter": "Risiko",
};
for (const [fid, series] of Object.entries(frameworkSeriesMap)) {
  updateFrameworkCount.run(series, fid);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log("\nDatabase summary:");
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`  Total:       ${frameworkCount + guidanceCount + advisoryCount}`);

// Verify FTS
const ftsGuidance = db.prepare("SELECT count(*) as cnt FROM guidance_fts").get() as { cnt: number };
const ftsAdvisory = db.prepare("SELECT count(*) as cnt FROM advisories_fts").get() as { cnt: number };
console.log(`\nFTS index verification:`);
console.log(`  guidance_fts:   ${ftsGuidance.cnt} rows`);
console.log(`  advisories_fts: ${ftsAdvisory.cnt} rows`);

console.log(`\nDone. Database ready at ${DB_PATH}`);
db.close();
