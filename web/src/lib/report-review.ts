import { type CVSS4BaseScore, isExtendedCVSS4Vector, scoreCVSS4Base } from "./cvss-v4";

const sectionNames = {
  summary: ["概述", "概览", "概覽", "漏洞概述", "summary", "overview", "executive summary", "finding summary"],
  impact: ["影响与危害", "影响", "影響與危害", "影響", "impact", "business impact", "impact and risk"],
  scope: [
    "受影响范围", "受影響範圍", "scope", "affected scope", "affected assets", "affected systems",
    "前置条件", "前置條件", "prerequisites", "preconditions",
  ],
  cause: ["根因分析", "根本原因", "root cause", "root cause analysis"],
  remediation: ["修复建议", "修復建議", "修复", "修復", "remediation", "recommendations", "mitigation"],
  description: ["描述", "漏洞描述", "description", "finding description", "vulnerability description"],
  testing: ["测试过程", "測試過程", "test process", "testing process", "testing", "test procedure"],
} as const;
export type ReportSectionId = keyof typeof sectionNames;
export type ReportSeverity = CVSS4BaseScore["severity"];
type SectionStatus = "present" | "empty" | "missing";
type CVSSStatus = "absent" | "invalid" | "unsupported" | "unscored" | "mismatch" | "match";
type Exchange = { requestLine: number | null; responseLine: number | null };

export interface ReportReview {
  profile: "delivery" | "legacy";
  sections: { id: ReportSectionId; status: SectionStatus }[];
  cvss: {
    status: CVSSStatus;
    score: number | null;
    severity: ReportSeverity | null;
    statedScore: number | null;
    statedSeverity: ReportSeverity | null;
  };
  http: { status: "absent" | "partial" | "paired" | "not-applicable"; exchanges: Exchange[] };
}

const sectionByName = new Map<string, ReportSectionId>();
for (const id of Object.keys(sectionNames) as ReportSectionId[]) {
  for (const name of sectionNames[id]) sectionByName.set(name, id);
}

type PacketKind = "request" | "response";
type Fragment =
  | { kind: "heading"; depth: number; text: string }
  | { kind: "text"; text: string }
  | { kind: "code"; filled: boolean; packet: PacketKind | null; line: number };

function packetKind(line: string): PacketKind | null {
  if (/^HTTP\/(?:1\.[01]|[23](?:\.0)?)\s+[1-5]\d{2}(?:\s|$)/.test(line)) return "response";
  if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP\/(?:1\.[01]|[23](?:\.0)?)$/.test(line)) {
    return "request";
  }
  return null;
}

// Retain only the first content line of a fence for classifying a packet.
// A status line inside a packet body must never create another exchange.
function* fragments(markdown: string): Generator<Fragment> {
  const lines = markdown.split(/\r\n?|\n/);
  let fence: { marker: string; inspect: boolean; line: number; packet: PacketKind | null } | null = null;
  let inComment = false;
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (fence) {
      const closing = /^ {0,3}(`{3,}|~{3,})[ \t]*$/.exec(line)?.[1];
      if (closing && closing[0] === fence.marker[0] && closing.length >= fence.marker.length) {
        yield { kind: "code", filled: fence.line > 0, packet: fence.packet, line: fence.line };
        fence = null;
      } else if (fence.line === 0 && line.trim()) {
        fence.line = i + 1;
        if (fence.inspect) fence.packet = packetKind(line.trim());
      }
      continue;
    }

    if (inComment) {
      const end = line.indexOf("-->");
      if (end < 0) continue;
      line = line.slice(end + 3);
      inComment = false;
    }
    line = line.replace(/<!--[\s\S]*?(-->|$)/g, (_, end: string) => {
      if (!end) inComment = true;
      return "";
    });
    const opening = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
    if (opening) {
      const language = opening[2].trim().toLowerCase();
      fence = {
        marker: opening[1],
        inspect: /^(?:http|https|http-request|http-response|text|plaintext)?$/.test(language),
        line: 0,
        packet: null,
      };
      continue;
    }
    if (!line.trim()) continue;
    if (/^(?: {4}|\t)/.test(line)) {
      yield { kind: "code", filled: true, packet: null, line: i + 1 };
      continue;
    }
    const heading = /^ {0,3}(#{1,6})[ \t]+(.+?)\s*$/.exec(line);
    const underline = /^ {0,3}(=+|-+)\s*$/.exec(lines[i + 1] ?? "");
    if (heading || underline) {
      const text = (heading ? heading[2].replace(/\s+#+$/, "") : line)
        .trim()
        .replace(/^(?:\d+[.)、]\s*)/, "")
        .toLowerCase();
      const depth = heading ? heading[1].length : underline?.[1][0] === "=" ? 1 : 2;
      if (!heading) i++;
      yield { kind: "heading", text, depth };
    } else {
      yield { kind: "text", text: line.trim() };
    }
  }
  if (fence) yield { kind: "code", filled: fence.line > 0, packet: fence.packet, line: fence.line };
}

const severityNames: Record<string, ReportSeverity> = {
  none: "none",
  无: "none",
  無: "none",
  low: "low",
  低危: "low",
  低: "low",
  medium: "medium",
  moderate: "medium",
  中危: "medium",
  中: "medium",
  high: "high",
  高危: "high",
  高: "high",
  critical: "critical",
  严重: "critical",
  嚴重: "critical",
};

function severityOf(text: string): ReportSeverity | null {
  const label = text.trim().toLowerCase();
  return Object.hasOwn(severityNames, label) ? severityNames[label] : null;
}

const metadataField =
  /^(?:CVSS(?:[- ]B)?(?:\s+v?4\.0)?\s*)?(?:(?:base\s+)?score\b|severity\b|[评評]分|分[数數]|漏洞等[级級]|[严嚴]重等[级級])(?:\s|[:：=])/i;

function checkCVSS(lines: Iterable<string>): ReportReview["cvss"] {
  const vectors = new Set<string>();
  const scores = new Set<number>();
  const severities = new Set<ReportSeverity>();
  let badClaim = false;
  let mentionsV4 = false;
  for (const raw of lines) {
    const text = raw.replace(/\*\*|__|`/g, "").replace(/^[-*]\s+/, "");
    const tokens = text.match(/\bCVSS:4\.0\b[^\s`|()<>{}\[\]，；。（）]*/gi) ?? [];
    for (const token of tokens) vectors.add(token.replace(/[.,;]+$/, ""));
    if (/^CVSS\s+(?:v?4\.0|4\b)/i.test(text)) mentionsV4 = true;

    // Interpret claims attached to a vector or to a labelled metadata field.
    if (!tokens.length && !metadataField.test(text)) continue;
    const claim = /(?:\b(?:base\s+)?score\b|[评評]分|分[数數])\s*[:：=]?\s*([^\s()（）,;，；|]+)/i.exec(text);
    if (claim) {
      if (/^(?:10(?:\.0)?|[0-9](?:\.\d)?)$/.test(claim[1])) scores.add(Number(claim[1]));
      else badClaim = true;
    }
    const explicit = /(?:\bseverity\b|漏洞等[级級]|[严嚴]重等[级級])\s*[:：=]\s*([^\s()（）,;，；|]+)/i.exec(text);
    const bracket = claim && /^\s*[（(]([^()（）]+)[)）]/.exec(text.slice(claim.index + claim[0].length));
    const parenthetical = bracket && severityOf(bracket[1]);
    if (parenthetical) severities.add(parenthetical);
    if (bracket && !parenthetical && !/^CVSS-B$/i.test(bracket[1])) badClaim = true;
    if (explicit) {
      const value = severityOf(explicit[1]);
      if (value) severities.add(value);
      else badClaim = true;
    }
  }
  const statedScore = scores.size === 1 ? [...scores][0] : null;
  const statedSeverity = severities.size === 1 ? [...severities][0] : null;
  const result: ReportReview["cvss"] = { status: "absent", score: null, severity: null, statedScore, statedSeverity };
  if (!vectors.size && !mentionsV4) return result;
  result.status = "invalid";
  if (vectors.size !== 1) return result;
  const [vector] = vectors;
  const calculated = scoreCVSS4Base(vector);
  if (!calculated) {
    if (isExtendedCVSS4Vector(vector)) result.status = "unsupported";
    return result;
  }
  result.score = calculated.score;
  result.severity = calculated.severity;
  if (
    badClaim ||
    scores.size > 1 ||
    severities.size > 1 ||
    (statedScore !== null && statedScore !== result.score) ||
    (statedSeverity !== null && statedSeverity !== result.severity)
  ) {
    result.status = "mismatch";
  } else {
    result.status = statedScore === null ? "unscored" : "match";
  }
  return result;
}

// Direction labels can share a section. A new section, a different identifier,
// prose, or another code block breaks the association with the prior request.
function packetLabel(text: string): { kind: PacketKind; id: string } | null {
  const match =
    /^(?:HTTP\s*)?(request|response|[请請]求|[响響]应|響應)(?:\s+(?:packet|message)|包|报文|報文)?(?:\s*(?:#|id\s*[:=]?)\s*([\w.-]+))?\s*[:：]?$/i.exec(
      text.replace(/\*\*|`/g, ""),
    );
  if (!match) return null;
  return { kind: /^(?:request|[请請]求)$/i.test(match[1]) ? "request" : "response", id: match[2] ?? "" };
}

function checkHttp(parts: Fragment[]): ReportReview["http"] {
  const exchanges: Exchange[] = [];
  let pending: { exchange: Exchange; id: string } | null = null;
  let label: ReturnType<typeof packetLabel> = null;
  let notApplicable = false;
  for (const part of parts) {
    if (part.kind !== "code") {
      const nextLabel = packetLabel(part.text);
      if (nextLabel) {
        label = nextLabel;
        if (label.kind === "request") pending = null;
        continue;
      }
      if (
        /^(?:(?:burp|http(?: evidence)?)\s*[:：]?\s*(?:not applicable|n\/a|不[适適]用)|(?:protocol\s*[:：]\s*)?non[- ]http\b|非\s*HTTP\b)/i.test(
          part.text,
        )
      )
        notApplicable = true;
      pending = null;
      label = null;
      continue;
    }
    const kind = part.packet;
    if (kind === "request") {
      const exchange = { requestLine: part.line, responseLine: null };
      exchanges.push(exchange);
      pending = label?.kind === "response" ? null : { exchange, id: label?.id ?? "" };
    } else if (kind === "response") {
      if (pending && label?.kind !== "request" && pending.id === (label?.id ?? "")) {
        pending.exchange.responseLine = part.line;
      } else {
        exchanges.push({ requestLine: null, responseLine: part.line });
      }
      pending = null;
    } else {
      pending = null;
    }
    label = null;
  }
  if (!exchanges.length) return { status: notApplicable ? "not-applicable" : "absent", exchanges };
  const partial = exchanges.some(({ requestLine, responseLine }) => requestLine === null || responseLine === null);
  return { status: partial ? "partial" : "paired", exchanges };
}

export function inspectReport(markdown: string): ReportReview {
  const parts = [...fragments(markdown)];
  const sections = new Map<ReportSectionId, SectionStatus>();
  const metadata: string[] = [];
  let current: { id: ReportSectionId; depth: number } | null = null;
  for (const part of parts) {
    if (part.kind === "heading") {
      if (current && part.depth <= current.depth) current = null;
      if (part.depth > 3) continue;
      const id = sectionByName.get(part.text);
      if (id) {
        current = { id, depth: part.depth };
        if (!sections.has(id)) sections.set(id, "empty");
      }
      continue;
    }
    if (part.kind === "text") metadata.push(part.text);
    if (current && (part.kind === "code" ? part.filled : /[\p{L}\p{N}]/u.test(part.text))) {
      sections.set(current.id, "present");
    }
  }
  const legacy = ["summary", "scope", "cause", "impact"] as const;
  const delivery = (sections.has("testing") || sections.has("description")) && !legacy.some((id) => sections.has(id));
  const required: ReportSectionId[] = delivery
    ? ["description", "testing", "remediation"]
    : ["summary", "impact", "scope", "cause", "remediation"];
  if (!delivery && !sections.has("summary") && sections.has("description")) {
    sections.set("summary", sections.get("description") ?? "empty");
  }
  return {
    profile: delivery ? "delivery" : "legacy",
    sections: required.map((id) => ({ id, status: sections.get(id) ?? "missing" })),
    cvss: checkCVSS(metadata),
    http: checkHttp(parts),
  };
}
