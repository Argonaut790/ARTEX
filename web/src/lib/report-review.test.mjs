import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import test from "node:test";

// The app uses extensionless imports. Resolve the one local scorer when Node
// runs TypeScript directly, without changing the production module resolver.
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    return nextResolve(specifier === "./cvss-v4" ? "./cvss-v4.ts" : specifier, context);
  },
});
const { inspectReport } = await import("./report-review.ts");
const { scoreCVSS4Base } = await import("./cvss-v4.ts");
hooks.deregister();

const example = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";
const zero = example.replace("/VC:L", "/VC:N");
const cvss = (text) => inspectReport(text).cvss;
const request = ["```http", "GET /example HTTP/1.1", "```"].join("\n");
const response = ["```http", "HTTP/1.1 200 OK", "```"].join("\n");
const statuses = (report) => Object.fromEntries(report.sections.map((section) => [section.id, section.status]));

test("v4.0 base scores agree with the eight FIRST reference cases in the port", () => {
  const cases = [
    ["AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3],
    ["AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1],
    ["AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5],
    ["AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2],
    ["AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1],
    ["AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3],
    ["AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7],
    ["AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2],
  ];
  for (const [metrics, expected] of cases) assert.equal(scoreCVSS4Base("CVSS:4.0/" + metrics)?.score, expected);
});

test("a delivery report can declare an incorrect score and severity", () => {
  assert.deepEqual(cvss("CVSS 4.0：" + example + " 评分 7.1（高危）"), {
    status: "mismatch",
    score: 6.9,
    severity: "medium",
    statedScore: 7.1,
    statedSeverity: "high",
  });
  assert.equal(cvss(example + " Score: 6.9 (Low)").status, "mismatch");
  assert.equal(cvss(example + " Score: 1.0 (Medium)").status, "mismatch");
});

test("zero is a real stated score and none is a severity", () => {
  const report = [
    "- **CVSS 4.0 Base 向量（CVSS-B）**：" + zero,
    "- **CVSS 4.0 评分**：0.0（CVSS-B）",
    "- **漏洞等级**：无",
  ];
  assert.deepEqual(cvss(report.join("\n")), {
    status: "match",
    score: 0,
    severity: "none",
    statedScore: 0,
    statedSeverity: "none",
  });
  assert.equal(cvss(zero + " Score: 0").status, "match");
  assert.equal(cvss(zero).status, "unscored");
  assert.equal(cvss(example + " Score: 0").status, "mismatch");
});

test("malformed vectors and conflicting claims cannot pass", () => {
  const invalid = [
    example.replace("/PR:N", "/AT:N"),
    example + "/AV:N",
    example.replace("/PR:N", ""),
    example.replace("/VC:L", "/VC:BAD"),
    example.replace("/AT:N/PR:N", "/PR:N/AT:N"),
    example.replace("/VC:L", "/vc:L"),
    example + "/",
    example + "/E:P/E:U",
    example + "/U:Yellow",
    example + "/OTHER:L",
  ];
  for (const bad of invalid) {
    assert.equal(cvss(bad + " Score: 6.9").status, "invalid", bad);
    assert.equal(scoreCVSS4Base(bad), null);
  }
  assert.equal(cvss(example + " Score: wrong").status, "mismatch");
  assert.equal(cvss(example + " Score: 6.9\nScore: 3.2").status, "mismatch");
  assert.equal(cvss(example + " Score: 6.9 (High)\nSeverity: Medium").status, "mismatch");
  assert.equal(cvss("Ordinary report.").status, "absent");
});

test("valid extended vectors do not acquire a base-only score", () => {
  for (const suffix of ["/E:P", "/CR:H/MAV:A/MSI:S", "/S:N/AU:Y/R:A/V:C/RE:H/U:Amber"]) {
    const result = cvss(example + suffix);
    assert.equal(result.status, "unsupported");
    assert.equal(result.score, null);
  }
});

test("legacy report profiles accept English, Chinese and the alternative prerequisites layout", () => {
  for (const names of [
    ["Summary", "Impact", "Affected scope", "Root cause", "Remediation"],
    ["概述", "影响与危害", "受影响范围", "根因分析", "修复建议"],
    ["概述", "影响", "前置条件", "根因分析", "修复建议"],
  ]) {
    const report = inspectReport(names.map((name) => "## " + name + "\nSample content.").join("\n"));
    assert.equal(report.profile, "legacy");
    assert.ok(report.sections.every((s) => s.status === "present"));
  }
});

test("detects missing and empty sections without counting prose, comments or fenced headings", () => {
  const report = inspectReport(
    [
      "Description",
      "-----------",
      "A sample.",
      "## Testing process",
      "The word Remediation in a sentence.",
      "<!--",
      "## Remediation",
      "-->",
      "~~~~text",
      "## Remediation",
      "~~~",
      example,
      "~~~~",
    ].join("\n"),
  );
  assert.deepEqual(statuses(report), { description: "present", testing: "present", remediation: "missing" });
  assert.equal(report.cvss.status, "absent");
  const empty = inspectReport("## 描述\n## 测试过程\n<!-- testing -->\n## 修复建议\nAddress the issue.");
  assert.deepEqual(statuses(empty), { description: "empty", testing: "empty", remediation: "present" });
});

test("counts recorded packets inside the same exchange and returns line numbers only", () => {
  const markdown = [
    "#### 证据绑定 7",
    "##### 请求包",
    "```http",
    "GET /sample-note HTTP/1.1",
    "X-Example: marker-for-test",
    "```",
    "##### 响应包",
    response,
  ].join("\n");
  assert.deepEqual(inspectReport(markdown).http, {
    status: "paired",
    exchanges: [{ requestLine: 4, responseLine: 9 }],
  });
  assert.doesNotMatch(JSON.stringify(inspectReport(markdown)), /sample-note|marker-for-test/);
});

test("different report sections, prose and different exchange IDs cannot create a pair", () => {
  for (const [requestLabel, separator] of [
    ["#### Exchange A", "#### Exchange B"],
    ["Request #14", "Response #15"],
    ["### A", "A separate sample follows."],
  ]) {
    const result = inspectReport([requestLabel, request, separator, response].join("\n")).http;
    assert.equal(result.status, "partial");
    assert.equal(result.exchanges.length, 2);
    assert.equal(result.exchanges[0].responseLine, null);
    assert.equal(result.exchanges[1].requestLine, null);
  }
  assert.equal(inspectReport(["Request #14", request, "Response #14", response].join("\n")).http.status, "paired");
});

test("recognizes a missing direction, ignores nested body text and respects explicit non-HTTP reports", () => {
  const embedded = ["```http", "GET /example HTTP/1.1", "", "HTTP/1.1 200 OK", "```"].join("\n");
  assert.deepEqual(inspectReport(embedded).http, {
    status: "partial",
    exchanges: [{ requestLine: 2, responseLine: null }],
  });
  assert.equal(inspectReport(response).http.status, "partial");
  assert.equal(inspectReport("Burp 不适用：本地记录。").http.status, "not-applicable");
  assert.equal(inspectReport("HTTP: N/A").http.status, "not-applicable");
  assert.equal(inspectReport("An HTTP reference.").http.status, "absent");
  assert.equal(inspectReport(["HTTP: N/A", request].join("\n")).http.status, "partial");
});
