import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  ArrowLeft,
  AlertTriangle,
  Info,
  ChevronDown,
  CheckCircle2,
  ExternalLink,
  Search,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { Background } from "@/components/landing/background";
import { Nav } from "@/components/landing/nav";
import { ScrollProgress } from "@/components/landing/scroll-progress";
import { getScan } from "@/lib/api/scans";
import type { Finding, SecurityReport, ScanStatusResponse, Severity } from "@/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/report/$scanId")({
  component: ReportPage,
});

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info: "text-muted-foreground bg-foreground/[0.03] border-border",
};

const GRADE_COLORS: Record<string, string> = {
  A: "text-emerald-400",
  "A-": "text-emerald-400",
  "B+": "text-lime-400",
  B: "text-yellow-400",
  "B-": "text-yellow-400",
  "C+": "text-orange-400",
  C: "text-orange-400",
  D: "text-red-400",
  F: "text-red-500",
};

function ReportPage() {
  const { scanId } = Route.useParams();
  const [data, setData] = useState<ScanStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getScan(scanId);
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load report");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [scanId]);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} onRetry={load} />;
  if (!data?.report) return <PendingState status={data?.status ?? null} />;

  const report = data.report;
  const filteredFindings = report.findings.filter((f) => {
    const matchesSeverity = filterSeverity === "all" || f.severity === filterSeverity;
    const matchesSearch =
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="relative min-h-screen">
      <Background />
      <ScrollProgress />
      <Nav />
      <main className="mx-auto max-w-5xl px-6 pb-32 pt-28">
        <ReportHeader report={report} />
        <ScoreSummary report={report} />
        {report.ai_summary && <AISummary report={report} />}
        <SecurityHeadersPanel headers={report.security_headers} />
        <FindingsPanel
          findings={filteredFindings}
          allFindings={report.findings}
          search={search}
          setSearch={setSearch}
          filterSeverity={filterSeverity}
          setFilterSeverity={setFilterSeverity}
          expandedId={expandedId}
          setExpandedId={setExpandedId}
        />
        <NetworkPanel requests={report.network_requests} />
        <CookiesPanel cookies={report.cookies} />
        <StoragePanel items={report.storage_items} />
        <SecretsPanel secrets={report.secrets} />
      </main>
    </div>
  );
}

function ReportHeader({ report }: { report: SecurityReport }) {
  return (
    <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
      <Link
        to="/scan"
        className="mb-6 inline-flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to scanner
      </Link>
      <h1 className="font-display text-3xl font-semibold tracking-tight sm:text-4xl">
        <span className="text-gradient">Security Report</span>
      </h1>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
        <span className="font-mono text-xs">{report.target_url}</span>
        <span>·</span>
        <span>Scanned {new Date(report.completed_at).toLocaleString()}</span>
        <span>·</span>
        <span>{report.duration_seconds}s scan</span>
        {report.tech_stack.length > 0 && (
          <>
            <span>·</span>
            <span>{report.tech_stack.join(", ")}</span>
          </>
        )}
      </div>
    </motion.div>
  );
}

function ScoreSummary({ report }: { report: SecurityReport }) {
  const gradeColor = GRADE_COLORS[report.grade] ?? "text-foreground";
  const severities: Array<{ label: string; count: number; color: string }> = [
    { label: "Critical", count: report.critical_count, color: "text-red-400" },
    { label: "High", count: report.high_count, color: "text-orange-400" },
    { label: "Medium", count: report.medium_count, color: "text-yellow-400" },
    { label: "Low", count: report.low_count, color: "text-blue-400" },
    { label: "Info", count: report.info_count, color: "text-muted-foreground" },
  ];
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.06 }}
      className="glass-strong mb-6 overflow-hidden rounded-2xl p-6"
    >
      <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
        <div className="text-center sm:w-32">
          <div className={`font-display text-6xl font-semibold ${gradeColor}`}>{report.grade}</div>
          <div className="mt-1 font-display text-2xl font-semibold">
            {report.score}
            <span className="text-sm text-muted-foreground">/100</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-foreground/10">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${report.score}%` }}
              transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1] }}
              className="h-full rounded-full"
              style={{ background: "linear-gradient(90deg, var(--primary), var(--accent))" }}
            />
          </div>
        </div>
        <div className="flex flex-1 flex-wrap gap-3">
          {severities.map((s) => (
            <div key={s.label} className="glass min-w-[90px] flex-1 rounded-xl p-3 text-center">
              <div className={`font-display text-2xl font-semibold tabular-nums ${s.color}`}>
                {s.count}
              </div>
              <div className="mt-0.5 text-xs text-muted-foreground">{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

function AISummary({ report }: { report: SecurityReport }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="glass mb-6 rounded-2xl p-5"
    >
      <div className="mb-3 flex items-center gap-2 text-xs font-medium text-primary">
        <Shield className="h-3.5 w-3.5" /> AI Security Summary
      </div>
      <p className="text-sm leading-relaxed text-foreground/85">{report.ai_summary}</p>
      {report.ai_recommendations.length > 0 && (
        <ul className="mt-4 space-y-2">
          {report.ai_recommendations.map((r, i) => (
            <li key={i} className="flex items-start gap-2.5 text-xs text-muted-foreground">
              <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full bg-primary/15 text-primary text-[9px] font-bold">
                {i + 1}
              </span>
              {r}
            </li>
          ))}
        </ul>
      )}
    </motion.div>
  );
}

function SecurityHeadersPanel({
  headers,
}: {
  report?: SecurityReport;
  headers: SecurityReport["security_headers"];
}) {
  const gradeColor = (g: string) => {
    if (g === "A") return "text-emerald-400";
    if (g === "B") return "text-lime-400";
    if (g === "C") return "text-yellow-400";
    if (g === "D") return "text-orange-400";
    return "text-red-400";
  };
  return (
    <Section title="Security Headers" delay={0.12}>
      <div className="overflow-hidden rounded-xl border border-border">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-foreground/[0.02] text-left text-muted-foreground">
              <th className="px-4 py-2.5 font-medium">Header</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Grade</th>
              <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Value</th>
            </tr>
          </thead>
          <tbody>
            {headers.map((h, i) => (
              <tr
                key={h.name}
                className={cn(
                  "border-b border-border/50 last:border-0",
                  i % 2 === 0 ? "" : "bg-foreground/[0.01]",
                )}
              >
                <td className="px-4 py-2.5 font-mono">{h.name}</td>
                <td className="px-4 py-2.5">
                  {h.present ? (
                    <span className="text-emerald-400">✓ Present</span>
                  ) : (
                    <span className="text-red-400">✕ Missing</span>
                  )}
                </td>
                <td className={cn("px-4 py-2.5 font-mono font-bold", gradeColor(h.grade))}>
                  {h.grade}
                </td>
                <td className="hidden max-w-[240px] truncate px-4 py-2.5 font-mono text-muted-foreground sm:table-cell">
                  {h.value ?? <span className="italic opacity-40">not set</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

interface FindingsPanelProps {
  findings: Finding[];
  allFindings: Finding[];
  search: string;
  setSearch: (v: string) => void;
  filterSeverity: Severity | "all";
  setFilterSeverity: (v: Severity | "all") => void;
  expandedId: string | null;
  setExpandedId: (id: string | null) => void;
}

function FindingsPanel({
  findings,
  allFindings,
  search,
  setSearch,
  filterSeverity,
  setFilterSeverity,
  expandedId,
  setExpandedId,
}: FindingsPanelProps) {
  const severities: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];
  return (
    <Section title={`Findings (${allFindings.length})`} delay={0.16}>
      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <div className="glass flex flex-1 items-center gap-2 rounded-full px-3 py-2">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings…"
            className="flex-1 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {severities.map((s) => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              className={cn(
                "rounded-full px-3 py-1 text-[11px] font-medium capitalize transition",
                filterSeverity === s
                  ? "bg-primary text-primary-foreground"
                  : "glass text-muted-foreground hover:text-foreground",
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>
      {findings.length === 0 ? (
        <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">
          {allFindings.length === 0
            ? "No findings — great posture!"
            : "No findings match your filter."}
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              expanded={expandedId === f.id}
              onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
            />
          ))}
        </div>
      )}
    </Section>
  );
}

function FindingCard({
  finding: f,
  expanded,
  onToggle,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className={cn("overflow-hidden rounded-xl border", SEVERITY_COLORS[f.severity])}>
      <button onClick={onToggle} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <SeverityBadge severity={f.severity} />
        <span className="flex-1 text-sm font-medium">{f.title}</span>
        <span className="text-xs capitalize text-muted-foreground">
          {f.category.replace("_", " ")}
        </span>
        <ChevronDown
          className={cn(
            "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
            expanded && "rotate-180",
          )}
        />
      </button>
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden border-t border-current/20"
          >
            <div className="space-y-3 p-4 text-xs">
              <p className="leading-relaxed text-foreground/80">{f.description}</p>
              {f.evidence && (
                <div>
                  <div className="mb-1 font-medium text-muted-foreground">Evidence</div>
                  <pre className="overflow-x-auto rounded-lg bg-foreground/[0.04] p-3 font-mono text-[11px]">
                    {f.evidence}
                  </pre>
                </div>
              )}
              {f.location && (
                <div>
                  <div className="mb-1 font-medium text-muted-foreground">Location</div>
                  <code className="text-[11px]">{f.location}</code>
                </div>
              )}
              <div>
                <div className="mb-1 font-medium text-muted-foreground">Recommendation</div>
                <p className="leading-relaxed">{f.recommendation}</p>
              </div>
              {f.references.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {f.references.map((r) => (
                    <a
                      key={r}
                      href={r}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-primary hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" /> {new URL(r).hostname}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function NetworkPanel({ requests }: { requests: SecurityReport["network_requests"] }) {
  const flagged = requests.filter((r) => r.flagged);
  const shown = requests.slice(0, 50);
  return (
    <Section
      title={`Network Requests (${requests.length}${flagged.length ? ` · ${flagged.length} flagged` : ""})`}
      delay={0.2}
    >
      <div className="overflow-x-auto rounded-xl border border-border">
        <table className="w-full min-w-[560px] text-xs">
          <thead>
            <tr className="border-b border-border bg-foreground/[0.02] text-left text-muted-foreground">
              <th className="px-4 py-2.5 font-medium">Method</th>
              <th className="px-4 py-2.5 font-medium">URL</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">ms</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => (
              <tr
                key={i}
                className={cn(
                  "border-b border-border/50 last:border-0",
                  r.flagged ? "bg-primary/5" : i % 2 === 0 ? "" : "bg-foreground/[0.01]",
                )}
              >
                <td className="px-4 py-2">
                  <span className="rounded bg-foreground/10 px-1.5 py-0.5 font-mono">
                    {r.method}
                  </span>
                </td>
                <td className="max-w-[320px] px-4 py-2">
                  <span
                    className={cn(
                      "font-mono truncate block",
                      r.flagged ? "text-primary" : "text-foreground/70",
                    )}
                  >
                    {r.url.length > 60 ? "…" + r.url.slice(-58) : r.url}
                  </span>
                  {r.flag_reason && (
                    <span className="text-[10px] text-primary/70">{r.flag_reason}</span>
                  )}
                </td>
                <td
                  className={cn(
                    "px-4 py-2 font-mono",
                    r.status < 300
                      ? "text-emerald-400/80"
                      : r.status < 400
                        ? "text-yellow-400"
                        : "text-primary",
                  )}
                >
                  {r.status}
                </td>
                <td className="px-4 py-2 text-muted-foreground">{r.duration_ms ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {requests.length > 50 && (
        <div className="mt-2 text-center text-xs text-muted-foreground">
          Showing 50 of {requests.length} requests
        </div>
      )}
    </Section>
  );
}

function CookiesPanel({ cookies }: { cookies: SecurityReport["cookies"] }) {
  if (!cookies.length) return null;
  return (
    <Section title={`Cookies (${cookies.length})`} delay={0.22}>
      <div className="space-y-2">
        {cookies.map((c, i) => (
          <div
            key={i}
            className={cn(
              "rounded-xl border px-4 py-3 text-xs",
              c.issues.length ? "border-primary/30 bg-primary/5" : "border-border",
            )}
          >
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono font-medium">{c.name}</span>
              <span className="text-muted-foreground">{c.domain}</span>
              <FlagBadge ok={c.secure} label="Secure" />
              <FlagBadge ok={c.http_only} label="HttpOnly" />
              <FlagBadge
                ok={!!c.same_site && c.same_site !== "None"}
                label={`SameSite=${c.same_site ?? "unset"}`}
              />
            </div>
            {c.issues.length > 0 && (
              <ul className="mt-2 space-y-1">
                {c.issues.map((issue, j) => (
                  <li key={j} className="flex items-center gap-1.5 text-primary/80">
                    <AlertTriangle className="h-3 w-3 shrink-0" /> {issue}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </Section>
  );
}

function StoragePanel({ items }: { items: SecurityReport["storage_items"] }) {
  if (!items.length) return null;
  const flagged = items.filter((i) => i.flagged);
  return (
    <Section
      title={`Storage (${items.length}${flagged.length ? ` · ${flagged.length} flagged` : ""})`}
      delay={0.24}
    >
      <div className="space-y-1.5">
        {items.map((item, i) => (
          <div
            key={i}
            className={cn(
              "flex items-start gap-3 rounded-lg px-3 py-2.5 text-xs",
              item.flagged ? "border border-primary/30 bg-primary/5" : "border border-border/50",
            )}
          >
            <span className="rounded bg-foreground/10 px-1.5 py-0.5 font-mono text-[10px] shrink-0">
              {item.storage_type}
            </span>
            <span className="font-mono font-medium">{item.key}</span>
            <span className="ml-auto font-mono text-muted-foreground truncate max-w-[180px]">
              {item.value_preview}
            </span>
            {item.flagged && <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-primary" />}
          </div>
        ))}
      </div>
    </Section>
  );
}

function SecretsPanel({ secrets }: { secrets: SecurityReport["secrets"] }) {
  if (!secrets.length) return null;
  return (
    <Section title={`Exposed Secrets (${secrets.length})`} delay={0.26}>
      <div className="space-y-2">
        {secrets.map((s, i) => (
          <div
            key={i}
            className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-xs"
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
            <div>
              <div className="font-medium text-red-400">{s.pattern_name}</div>
              <div className="mt-0.5 font-mono text-muted-foreground">{s.location}</div>
              <div className="mt-1 font-mono">{s.value_preview}</div>
            </div>
            <span className="ml-auto rounded-full bg-red-500/10 px-2 py-0.5 text-[10px] text-red-400">
              {Math.round(s.confidence * 100)}% confidence
            </span>
          </div>
        ))}
      </div>
    </Section>
  );
}

function Section({
  title,
  children,
  delay = 0,
}: {
  title: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, ease: [0.22, 1, 0.36, 1] }}
      className="mb-8"
    >
      <h2 className="mb-3 font-display text-sm font-semibold tracking-tight text-muted-foreground uppercase">
        {title}
      </h2>
      {children}
    </motion.div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
        SEVERITY_COLORS[severity],
      )}
    >
      {severity}
    </span>
  );
}

function FlagBadge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1",
        ok ? "text-emerald-400/80" : "text-red-400/70",
      )}
    >
      {ok ? <CheckCircle2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
      {label}
    </span>
  );
}

function LoadingState() {
  return (
    <div className="relative min-h-screen">
      <Background />
      <Nav />
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="mx-auto mb-4 h-8 w-8 animate-spin text-primary" />
          <div className="text-sm text-muted-foreground">Loading report…</div>
        </div>
      </div>
    </div>
  );
}

function ErrorState({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div className="relative min-h-screen">
      <Background />
      <Nav />
      <div className="flex min-h-screen items-center justify-center">
        <div className="glass max-w-sm rounded-2xl p-8 text-center">
          <AlertTriangle className="mx-auto mb-4 h-8 w-8 text-primary" />
          <div className="mb-2 font-medium">Failed to load report</div>
          <div className="mb-6 text-sm text-muted-foreground">{error}</div>
          <button
            onClick={onRetry}
            className="inline-flex items-center gap-2 rounded-full bg-primary px-5 py-2 text-sm font-medium text-primary-foreground"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        </div>
      </div>
    </div>
  );
}

function PendingState({ status }: { status: string | null }) {
  return (
    <div className="relative min-h-screen">
      <Background />
      <Nav />
      <div className="flex min-h-screen items-center justify-center">
        <div className="glass max-w-sm rounded-2xl p-8 text-center">
          <Loader2 className="mx-auto mb-4 h-8 w-8 animate-spin text-primary" />
          <div className="mb-2 font-medium">Scan in progress</div>
          <div className="mb-6 text-sm text-muted-foreground">Status: {status ?? "unknown"}</div>
          <Link
            to="/scan"
            className="inline-flex items-center gap-2 rounded-full border border-border px-5 py-2 text-sm"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> View progress
          </Link>
        </div>
      </div>
    </div>
  );
}
