"use client";

import { useMemo, useState } from "react";

import type { UITranslate } from "@/i18n/use-ui-translation";
import { inspectReport, type ReportReview } from "@/lib/report-review";

function scoreLabel(score: number | null, severity: ReportReview["cvss"]["severity"], ui: UITranslate) {
  const parts: string[] = [];
  if (score !== null) parts.push(score.toFixed(1));
  if (severity) parts.push(ui(severity === "none" ? "reportReview.none" : `status.severity.${severity}`));
  return parts.join(" · ");
}

export function FindingReportReview({ report, ui }: { report: string; ui: UITranslate }) {
  const [opened, setOpened] = useState(false);
  const review = useMemo(() => (opened ? inspectReport(report) : null), [opened, report]);

  return (
    <details
      className="min-w-0 rounded-lg border bg-card text-card-foreground"
      onToggle={(event) => setOpened(event.currentTarget.open)}
    >
      <summary className="cursor-pointer rounded-lg px-4 py-3 text-sm font-medium focus-visible:outline-ring">
        {ui("reportReview.title")}
      </summary>
      {review && (
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
