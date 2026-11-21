"use client";

import { useMemo, useState } from "react";

import type { UITranslate } from "@/i18n/use-ui-translation";
import { inspectReport, type ReportReview } from "@/lib/report-review";

// A saved report can contain large HTTP captures. Scan those only when the reader expands the review.
const AUTO_REVIEW_CHAR_LIMIT = 64 * 1024;

function reviewSummary(review: ReportReview, ui: UITranslate) {
  const sectionIssues = review.sections.filter(({ status }) => status !== "present").length;
  const scoreIssue = review.cvss.status === "invalid" || review.cvss.status === "mismatch";
  const incompletePairs = review.http.exchanges.reduce(
    (count, { requestLine, responseLine }) => count + Number(requestLine === null || responseLine === null),
    0,
  );
  const count = sectionIssues + Number(scoreIssue) + incompletePairs;
  if (count) return ui("reportReview.summary.issues", { count });

  const notes: string[] = [];
  if (review.cvss.status !== "match") notes.push(ui(`reportReview.summary.cvss.${review.cvss.status}`));
  if (review.http.status === "absent" || review.http.status === "not-applicable") {
    notes.push(ui(`reportReview.summary.http.${review.http.status}`));
  }
  return notes.length ? notes.join(" · ") : ui("reportReview.summary.clear");
}

function scoreLabel(score: number | null, severity: ReportReview["cvss"]["severity"], ui: UITranslate) {
  const parts: string[] = [];
  if (score !== null) parts.push(score.toFixed(1));
  if (severity) parts.push(ui(severity === "none" ? "reportReview.none" : `status.severity.${severity}`));
  return parts.join(" · ");
}

export function FindingReportReview({ report, ui }: { report: string; ui: UITranslate }) {
  const [disclosure, setDisclosure] = useState<"initial" | "open" | "closed">("initial");
  const shouldInspect = report.length <= AUTO_REVIEW_CHAR_LIMIT || disclosure !== "initial";
  const review = useMemo(() => (shouldInspect ? inspectReport(report) : null), [shouldInspect, report]);
  const summary = useMemo(() => (review ? reviewSummary(review, ui) : ui("reportReview.summary.deferred")), [review, ui]);

  return (
    <details
      className="min-w-0 rounded-xl bg-card text-card-foreground ring-1 ring-foreground/10"
      onToggle={(event) => setDisclosure(event.currentTarget.open ? "open" : "closed")}
    >
      <summary className="cursor-pointer rounded-xl px-4 py-3 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
        <span className="font-medium">{ui("reportReview.title")}</span>{" "}
        <span className="ml-1 text-xs text-muted-foreground">{summary}</span>
      </summary>
      {disclosure === "open" && review && (
        <div className="space-y-4 border-t px-4 py-3 text-sm">
          <div>
            <h3 className="font-medium">{ui("reportReview.sections")}</h3>
            <dl className="mt-1 grid gap-x-6 gap-y-1 sm:grid-cols-2">
              {review.sections.map(({ id, status }) => (
                <div key={id} className="flex flex-wrap justify-between gap-x-2">
                  <dt>{ui(`reportReview.section.${id}`)}</dt>
                  <dd className={status === "present" ? "text-muted-foreground" : "font-medium"}>
                    {ui(`reportReview.section.${status}`)}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
          <div>
            <h3 className="font-medium">{ui("reportReview.cvss")}</h3>
            <p>{ui(`reportReview.cvss.${review.cvss.status}`)}</p>
            <dl className="mt-1 flex flex-wrap gap-x-5 gap-y-1">
              {[
                ["reportReview.calculated", scoreLabel(review.cvss.score, review.cvss.severity, ui)],
                ["reportReview.stated", scoreLabel(review.cvss.statedScore, review.cvss.statedSeverity, ui)],
              ].map(([label, value]) =>
                value ? (
                  <div key={label} className="flex gap-2">
                    <dt className="text-muted-foreground">{ui(label)}</dt>
                    <dd className="tabular-nums">{value}</dd>
                  </div>
                ) : null,
              )}
            </dl>
            <a className="text-xs text-muted-foreground underline underline-offset-2" href="/third-party-notices.txt">
              {ui("reportReview.notices")}
            </a>
          </div>
          <div>
            <h3 className="font-medium">{ui("reportReview.http")}</h3>
            <p>{ui(`reportReview.http.${review.http.status}`)}</p>
            {review.http.exchanges.length > 0 && (
              <figure className="mt-2">
                <figcaption className="text-xs text-muted-foreground">{ui("reportReview.http.locations")}</figcaption>
                <p className="mt-1 max-h-40 overflow-auto whitespace-pre-line text-sm tabular-nums">
                  {review.http.exchanges
                    .map(({ requestLine, responseLine }) =>
                      [
                        requestLine === null
                          ? ui("reportReview.http.noRequest")
                          : ui("reportReview.http.request", { line: requestLine }),
                        responseLine === null
                          ? ui("reportReview.http.noResponse")
                          : ui("reportReview.http.response", { line: responseLine }),
                      ].join(" · "),
                    )
                    .join("\n")}
                </p>
              </figure>
            )}
          </div>
        </div>
      )}
    </details>
  );
}
