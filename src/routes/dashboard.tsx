import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect } from "react";
import { motion } from "motion/react";
import {
  Shield,
  ArrowRight,
  RefreshCw,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Globe,
  Activity,
} from "lucide-react";
import { Background } from "@/components/landing/background";
import { Nav } from "@/components/landing/nav";
import { ScrollProgress } from "@/components/landing/scroll-progress";
import { useDashboardStore } from "@/stores/dashboard-store";
import type { ScanSummary } from "@/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/dashboard")({
  component: DashboardPage,
});

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

const STATUS_COLORS: Record<string, string> = {
  completed: "text-emerald-400",
  failed: "text-red-400",
  cancelled: "text-muted-foreground",
};

function DashboardPage() {
  const { scans, loading, error, fetch } = useDashboardStore();

  useEffect(() => {
    fetch();
  }, []);

  const completedScans = scans.filter((s) => s.status === "completed");
  const avgScore = completedScans.length
    ? Math.round(completedScans.reduce((acc, s) => acc + (s.score ?? 0), 0) / completedScans.length)
    : null;
  const totalCritical = completedScans.reduce((acc, s) => acc + s.critical_count, 0);
  const totalHigh = completedScans.reduce((acc, s) => acc + s.high_count, 0);
  const activeScans = scans.filter((s) => !["completed", "failed", "cancelled"].includes(s.status));

  return (
    <div className="relative min-h-screen">
      <Background />
      <ScrollProgress />
      <Nav />
      <main className="mx-auto max-w-6xl px-6 pb-32 pt-28">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-10 flex items-center justify-between"
        >
          <div>
            <h1 className="font-display text-3xl font-semibold tracking-tight">
              <span className="text-gradient">Dashboard</span>
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">All scans run in this session</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={fetch}
              disabled={loading}
              className="glass inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm transition hover:scale-[1.01]"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </button>
            <Link
              to="/scan"
              className="inline-flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110"
              style={{ boxShadow: "0 12px 30px -12px var(--glow)" }}
            >
              New Scan <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </motion.div>

        {/* Stats row */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.06 }}
          className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-4"
        >
          <StatCard icon={Activity} label="Total Scans" value={scans.length} />
          <StatCard
            icon={CheckCircle2}
            label="Completed"
            value={completedScans.length}
            valueClass="text-emerald-400"
          />
          <StatCard
            icon={Shield}
            label="Avg Score"
            value={avgScore !== null ? `${avgScore}/100` : "—"}
          />
          <StatCard
            icon={AlertTriangle}
            label="Critical Issues"
            value={totalCritical}
            valueClass={totalCritical > 0 ? "text-red-400" : ""}
          />
        </motion.div>

        {/* Active scans */}
        {activeScans.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mb-6"
          >
            <h2 className="mb-3 text-xs font-medium uppercase tracking-widest text-muted-foreground">
              Active
            </h2>
            <div className="space-y-2">
              {activeScans.map((s) => (
                <ActiveScanRow key={s.scan_id} scan={s} />
              ))}
            </div>
          </motion.div>
        )}

        {/* Scan history */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.14 }}
        >
          <h2 className="mb-3 text-xs font-medium uppercase tracking-widest text-muted-foreground">
            History ({scans.length})
          </h2>

          {loading && scans.length === 0 ? (
            <div className="glass rounded-2xl p-12 text-center">
              <Loader2 className="mx-auto mb-3 h-6 w-6 animate-spin text-primary" />
              <div className="text-sm text-muted-foreground">Loading…</div>
            </div>
          ) : error ? (
            <div className="glass rounded-2xl p-8 text-center">
              <AlertTriangle className="mx-auto mb-3 h-6 w-6 text-primary" />
              <div className="mb-1 text-sm font-medium">Could not reach backend</div>
              <div className="text-xs text-muted-foreground">{error}</div>
            </div>
          ) : scans.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="overflow-hidden rounded-2xl border border-border">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border bg-foreground/[0.02] text-left text-muted-foreground">
                    <th className="px-4 py-3 font-medium">URL</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Score</th>
                    <th className="hidden px-4 py-3 font-medium sm:table-cell">Issues</th>
                    <th className="hidden px-4 py-3 font-medium sm:table-cell">Duration</th>
                    <th className="px-4 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan, i) => (
                    <ScanRow key={scan.scan_id} scan={scan} odd={i % 2 !== 0} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      </main>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  valueClass = "",
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  valueClass?: string;
}) {
  return (
    <div className="glass rounded-xl p-4">
      <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className={cn("font-display text-2xl font-semibold tabular-nums", valueClass)}>
        {value}
      </div>
    </div>
  );
}

function ActiveScanRow({ scan }: { scan: ScanSummary }) {
  return (
    <div className="glass flex items-center gap-4 rounded-xl px-4 py-3">
      <span className="relative flex h-2 w-2 shrink-0">
        <span className="absolute inset-0 animate-ping rounded-full bg-primary/70" />
        <span className="relative h-2 w-2 rounded-full bg-primary" />
      </span>
      <span className="flex-1 truncate font-mono text-xs">{scan.url}</span>
      <span className="text-xs text-muted-foreground capitalize">
        {scan.status.replace(/_/g, " ")}
      </span>
      <div className="w-24">
        <div className="h-1 overflow-hidden rounded-full bg-foreground/10">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${scan.progress}%`,
              background: "linear-gradient(90deg, var(--primary), var(--accent))",
            }}
          />
        </div>
        <div className="mt-0.5 text-right font-mono text-[10px] text-muted-foreground">
          {scan.progress}%
        </div>
      </div>
      <Link to="/scan" className="text-xs text-primary hover:underline">
        View
      </Link>
    </div>
  );
}

function ScanRow({ scan, odd }: { scan: ScanSummary; odd: boolean }) {
  const gradeColor = scan.grade ? (GRADE_COLORS[scan.grade] ?? "") : "";
  const statusColor = STATUS_COLORS[scan.status] ?? "text-muted-foreground";

  return (
    <tr className={cn("border-b border-border/50 last:border-0", odd && "bg-foreground/[0.01]")}>
      <td className="max-w-[200px] px-4 py-3">
        <div className="flex items-center gap-2">
          <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
          <span className="truncate font-mono">{scan.url.replace(/^https?:\/\//, "")}</span>
        </div>
      </td>
      <td className={cn("px-4 py-3 capitalize", statusColor)}>
        {scan.status === "completed" ? (
          <span className="flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" /> Done
          </span>
        ) : (
          scan.status.replace(/_/g, " ")
        )}
      </td>
      <td className="px-4 py-3">
        {scan.grade ? (
          <span className={cn("font-display font-bold", gradeColor)}>
            {scan.grade}{" "}
            <span className="font-mono text-muted-foreground font-normal">{scan.score}</span>
          </span>
        ) : (
          "—"
        )}
      </td>
      <td className="hidden px-4 py-3 sm:table-cell">
        {scan.critical_count > 0 && (
          <span className="text-red-400 mr-2">{scan.critical_count} crit</span>
        )}
        {scan.high_count > 0 && <span className="text-orange-400">{scan.high_count} high</span>}
        {!scan.critical_count && !scan.high_count && "—"}
      </td>
      <td className="hidden px-4 py-3 text-muted-foreground sm:table-cell">
        {scan.duration_seconds ? `${scan.duration_seconds}s` : "—"}
      </td>
      <td className="px-4 py-3">
        {scan.status === "completed" && (
          <Link
            to="/report/$scanId"
            params={{ scanId: scan.scan_id }}
            className="text-xs text-primary hover:underline"
          >
            Report →
          </Link>
        )}
      </td>
    </tr>
  );
}

function EmptyState() {
  return (
    <div className="glass rounded-2xl p-12 text-center">
      <Shield className="mx-auto mb-4 h-8 w-8 text-muted-foreground/40" />
      <div className="mb-2 font-medium text-muted-foreground">No scans yet</div>
      <div className="mb-6 text-xs text-muted-foreground/60">
        Run your first scan to see results here.
      </div>
      <Link
        to="/scan"
        className="inline-flex items-center gap-2 rounded-full bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground"
      >
        Start a scan <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}
