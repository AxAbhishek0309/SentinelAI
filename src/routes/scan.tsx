import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { motion, AnimatePresence } from "motion/react";
import { useEffect, useRef } from "react";
import {
  Shield,
  ArrowRight,
  X,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Info,
  Loader2,
  Globe,
  StopCircle,
} from "lucide-react";
import { Background } from "@/components/landing/background";
import { Nav } from "@/components/landing/nav";
import { ScrollProgress } from "@/components/landing/scroll-progress";
import { useScanStore } from "@/stores/scan-store";
import type { ScanLogEntry, ScanStatus } from "@/types";
import { TERMINAL_STATUSES } from "@/types";

export const Route = createFileRoute("/scan")({
  component: ScanPage,
});

const STEP_LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  initializing: "Initializing browser environment",
  launching_browser: "Launching headless Chromium",
  collecting_requests: "Collecting network requests",
  exploring_pages: "Exploring pages",
  analyzing_javascript: "Analyzing JavaScript & storage",
  inspecting_headers: "Inspecting security headers",
  checking_cookies: "Auditing cookies",
  finding_secrets: "Scanning for secrets",
  generating_report: "Generating AI report",
  completed: "Scan complete",
  failed: "Scan failed",
  cancelled: "Cancelled",
};

const STEP_ORDER: ScanStatus[] = [
  "queued",
  "initializing",
  "launching_browser",
  "collecting_requests",
  "exploring_pages",
  "analyzing_javascript",
  "inspecting_headers",
  "checking_cookies",
  "finding_secrets",
  "generating_report",
  "completed",
];

function ScanPage() {
  const navigate = useNavigate();
  const {
    url,
    setUrl,
    scanId,
    status,
    progress,
    currentStep,
    logs,
    report,
    error,
    startScan,
    cancelScan,
    reset,
  } = useScanStore();

  const logEndRef = useRef<HTMLDivElement>(null);

  // On mount: if no scan is actively running, clear previous results so the
  // page always starts fresh. Preserves the URL field so the user doesn't
  // have to retype it, but wipes logs/progress/report from the last session.
  useEffect(() => {
    if (status === null || TERMINAL_STATUSES.includes(status)) {
      reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs.length]);

  // Navigate to report when done
  useEffect(() => {
    if (status === "completed" && scanId) {
      const timer = setTimeout(() => navigate({ to: "/report/$scanId", params: { scanId } }), 1200);
      return () => clearTimeout(timer);
    }
  }, [status, scanId, navigate]);

  const isActive = status !== null && !TERMINAL_STATUSES.includes(status);
  const isDone = status === "completed";
  const isFailed = status === "failed" || status === "cancelled";
  const idle = status === null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    await startScan();
  };

  const currentStepIndex = status ? STEP_ORDER.indexOf(status) : -1;

  return (
    <div className="relative min-h-screen">
      <Background />
      <ScrollProgress />
      <Nav />

      <main className="mx-auto max-w-4xl px-6 pb-32 pt-28">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
          className="mb-10 text-center"
        >
          <span className="glass mb-4 inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs text-muted-foreground">
            <span className="relative flex h-2 w-2">
              {isActive && (
                <span className="absolute inset-0 animate-ping rounded-full bg-primary/70" />
              )}
              <span className="relative h-2 w-2 rounded-full bg-primary" />
            </span>
            {isActive ? "Scan in progress" : "Security Scanner"}
          </span>
          <h1 className="text-balance font-display text-4xl font-semibold tracking-tight sm:text-5xl">
            <span className="text-gradient">Scan your application</span>
          </h1>
          <p className="mt-3 text-sm text-muted-foreground">
            Paste your deployed app URL. Sentinel launches a real browser, crawls every page, and
            reports every vulnerability.
          </p>
        </motion.div>

        {/* URL Input */}
        <motion.form
          onSubmit={handleSubmit}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.08, ease: [0.22, 1, 0.36, 1] }}
          className="glass-strong mb-6 overflow-hidden rounded-2xl"
        >
          <div className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
            <div className="glass flex flex-1 items-center gap-3 rounded-full px-4 py-2.5">
              <Lock className="h-4 w-4 shrink-0 text-muted-foreground" />
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isActive}
                className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground disabled:opacity-60"
                placeholder="https://your-app.com"
                spellCheck={false}
                autoComplete="off"
                aria-label="Target URL"
              />
              {url && !isActive && (
                <button
                  type="button"
                  onClick={() => setUrl("")}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
            <div className="flex gap-2">
              {isActive ? (
                <button
                  type="button"
                  onClick={cancelScan}
                  className="inline-flex items-center gap-2 rounded-full border border-border px-5 py-2.5 text-sm font-medium text-foreground transition hover:bg-foreground/5"
                >
                  <StopCircle className="h-4 w-4" />
                  Cancel
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!url.trim()}
                  className="inline-flex items-center gap-2 rounded-full bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition hover:brightness-110 disabled:opacity-50"
                  style={{ boxShadow: "0 12px 30px -12px var(--glow)" }}
                >
                  {isFailed ? "Retry Scan" : "Start Scan"}
                  <ArrowRight className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>

          {/* Progress bar */}
          <div className="h-0.5 w-full bg-foreground/[0.04]">
            <motion.div
              animate={{ width: `${progress}%` }}
              transition={{ ease: [0.22, 1, 0.36, 1] }}
              className="h-full"
              style={{ background: "linear-gradient(90deg, var(--primary), var(--accent))" }}
            />
          </div>
        </motion.form>

        {/* Error */}
        <AnimatePresence>
          {isFailed && error && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mb-6 flex items-start gap-3 rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <div className="font-medium">Scan failed</div>
                <div className="mt-0.5 text-xs opacity-80">{error}</div>
              </div>
              <button onClick={reset} className="ml-auto">
                <X className="h-4 w-4" />
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Success redirect notice */}
        <AnimatePresence>
          {isDone && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mb-6 flex items-center gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400"
            >
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>Scan complete — opening report…</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Active scan panels */}
        <AnimatePresence>
          {!idle && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="grid gap-4 lg:grid-cols-[1fr_1.6fr]"
            >
              {/* Steps */}
              <div className="glass rounded-2xl p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="text-sm font-medium">Steps</h3>
                  <span className="font-mono text-xs text-primary">{progress}%</span>
                </div>
                <ol className="space-y-2">
                  {STEP_ORDER.filter((s) => s !== "failed" && s !== "cancelled").map((s, i) => {
                    const done = currentStepIndex > i;
                    const active = currentStepIndex === i;
                    return (
                      <li key={s} className="flex items-center gap-3">
                        <span
                          className={`relative flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] ${
                            done
                              ? "bg-emerald-500/20 text-emerald-400"
                              : active
                                ? "bg-primary/20 text-primary"
                                : "bg-foreground/[0.04] text-muted-foreground/50"
                          }`}
                        >
                          {active && (
                            <span className="absolute inset-0 animate-ping rounded-full bg-primary/30" />
                          )}
                          {done ? <CheckCircle2 className="h-3 w-3" /> : <span>{i + 1}</span>}
                        </span>
                        <span
                          className={`text-xs ${
                            done
                              ? "text-foreground/60 line-through"
                              : active
                                ? "font-medium text-foreground"
                                : "text-muted-foreground/50"
                          }`}
                        >
                          {STEP_LABELS[s]}
                        </span>
                        {active && (
                          <Loader2 className="ml-auto h-3 w-3 animate-spin text-primary" />
                        )}
                      </li>
                    );
                  })}
                </ol>
              </div>

              {/* Live log */}
              <div className="glass flex flex-col rounded-2xl overflow-hidden">
                <div className="flex items-center justify-between border-b border-border px-4 py-3">
                  <div className="flex items-center gap-2">
                    <Globe className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-medium">Live output</span>
                  </div>
                  <span className="font-mono text-[10px] text-muted-foreground truncate max-w-[200px]">
                    {url}
                  </span>
                </div>
                <div className="flex-1 overflow-y-auto p-4 font-mono text-xs min-h-[260px] max-h-[340px]">
                  <AnimatePresence initial={false}>
                    {logs.length === 0 && (
                      <div className="text-muted-foreground/50">Waiting for output…</div>
                    )}
                    {logs.map((l, i) => (
                      <LogLine key={i} log={l} />
                    ))}
                  </AnimatePresence>
                  <div ref={logEndRef} />
                </div>
                {currentStep && (
                  <div className="border-t border-border px-4 py-2 text-[11px] text-muted-foreground">
                    {isActive && <Loader2 className="mr-1.5 inline h-3 w-3 animate-spin" />}
                    {currentStep}
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Idle hint */}
        {idle && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-8 grid gap-3 sm:grid-cols-3"
          >
            {[
              {
                icon: Shield,
                title: "Real browser",
                desc: "Headless Chromium crawls every page exactly as a user would.",
              },
              {
                icon: Globe,
                title: "Network + headers",
                desc: "Every request, cookie, header and storage key is inspected.",
              },
              {
                icon: CheckCircle2,
                title: "AI report",
                desc: "GPT-4o explains findings and generates fix-it code snippets.",
              },
            ].map((c) => (
              <div key={c.title} className="glass rounded-xl p-4">
                <c.icon className="mb-2 h-4 w-4 text-primary" />
                <div className="text-xs font-medium">{c.title}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">{c.desc}</div>
              </div>
            ))}
          </motion.div>
        )}
      </main>
    </div>
  );
}

function LogLine({ log }: { log: ScanLogEntry }) {
  const colors = {
    info: "text-muted-foreground",
    warn: "text-primary",
    error: "text-destructive",
    ok: "text-emerald-400/90",
  };
  const icons = { info: "›", warn: "!", error: "✕", ok: "✓" };

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className={`flex items-start gap-2 py-0.5 ${colors[log.level]}`}
    >
      <span className="mt-px shrink-0 w-3">{icons[log.level]}</span>
      <span className="text-foreground/80">{log.message}</span>
    </motion.div>
  );
}
