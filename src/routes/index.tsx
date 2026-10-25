import { createFileRoute, Link } from "@tanstack/react-router";
import { motion, useScroll, useTransform, AnimatePresence } from "motion/react";
import { useEffect, useRef, useState } from "react";
import {
  Shield,
  Play,
  ArrowRight,
  Zap,
  Eye,
  KeyRound,
  Network,
  Cookie,
  Database,
  FileText,
  Radar,
  Sparkles,
  GitBranch,
  Chrome,
  Bell,
  Users,
  Github,
  ChevronDown,
  Check,
  Lock,
  Activity,
} from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Background } from "@/components/landing/background";
import { Nav } from "@/components/landing/nav";
import { ThemeToggle } from "@/components/landing/theme-toggle";
import { ScrollProgress } from "@/components/landing/scroll-progress";
import { SpotlightCard } from "@/components/landing/spotlight-card";

export const Route = createFileRoute("/")({
  component: Landing,
});

const ease = [0.22, 1, 0.36, 1] as const;
const spring = { type: "spring" as const, stiffness: 120, damping: 20, mass: 0.6 };

function fadeUp(delay = 0) {
  return {
    initial: { opacity: 0, y: 28, filter: "blur(10px)" },
    whileInView: { opacity: 1, y: 0, filter: "blur(0px)" },
    viewport: { once: true, margin: "-80px" },
    transition: { ...spring, delay },
  } as const;
}

/* -------------------- HERO -------------------- */

function Hero() {
  const ref = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end start"] });
  const heroScale = useTransform(scrollYProgress, [0, 1], [1, 0.9]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.8], [1, 0]);
  const browserRotate = useTransform(scrollYProgress, [0, 1], [0, -6]);
  const browserY = useTransform(scrollYProgress, [0, 1], [0, 60]);

  return (
    <section ref={ref} className="relative min-h-screen overflow-hidden pt-28">
      {/* ambient hero light */}
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-24 -z-0 h-[720px] w-[900px] -translate-x-1/2"
        style={{
          background:
            "radial-gradient(ellipse at center, color-mix(in oklab, var(--primary) 22%, transparent), transparent 65%)",
          filter: "blur(30px)",
        }}
      />
      <motion.div
        style={{ scale: heroScale, opacity: heroOpacity }}
        className="relative mx-auto grid max-w-7xl gap-16 px-6 pb-24 pt-6 lg:grid-cols-[1.05fr_1fr] lg:gap-10"
      >
        {/* Left */}
        <div className="flex flex-col justify-center">
          <motion.div {...fadeUp(0)} className="mb-6">
            <span className="glass inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs text-muted-foreground">
              <span className="relative flex h-2 w-2">
                <span className="absolute inset-0 animate-ping rounded-full bg-primary/70" />
                <span className="relative h-2 w-2 rounded-full bg-primary" />
              </span>
              Autonomous AI Security Agent — v1.0 Beta
            </span>
          </motion.div>

          <motion.h1
            {...fadeUp(0.05)}
            className="text-balance font-display text-6xl font-semibold leading-[0.95] tracking-tight sm:text-7xl lg:text-[5.5rem]"
          >
            <span className="text-gradient block">Deploy.</span>
            <span className="text-gradient block">Scan.</span>
            <span className="text-gradient-orange block">Trust.</span>
          </motion.h1>

          <motion.p
            {...fadeUp(0.15)}
            className="mt-8 max-w-xl text-balance text-lg leading-relaxed text-muted-foreground"
          >
            Sentinel AI autonomously explores your deployed application, discovers exposed secrets,
            analyzes security posture, and generates actionable reports.
          </motion.p>

          <motion.div {...fadeUp(0.25)} className="mt-10 flex flex-wrap items-center gap-3">
            <Link
              to="/scan"
              className="group relative inline-flex items-center gap-2 rounded-full bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition hover:scale-[1.02] active:scale-[0.98]"
              style={{ boxShadow: "0 20px 60px -20px var(--glow), 0 0 0 1px var(--border)" }}
            >
              <Radar className="h-4 w-4" />
              Start Scan
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <a
              href="#demo"
              className="glass inline-flex items-center gap-2 rounded-full px-6 py-3 text-sm font-medium text-foreground transition hover:scale-[1.02]"
            >
              <Play className="h-4 w-4" />
              Watch Demo
            </a>
          </motion.div>

          <motion.div
            {...fadeUp(0.35)}
            className="mt-14 flex items-center gap-8 text-xs text-muted-foreground"
          >
            <div className="flex items-center gap-2">
              <Lock className="h-3.5 w-3.5 text-primary" /> SOC 2 in progress
            </div>
            <div className="flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-primary" /> Zero data retention
            </div>
            <div className="hidden items-center gap-2 md:flex">
              <Activity className="h-3.5 w-3.5 text-primary" /> Real-time reports
            </div>
          </motion.div>
        </div>

        {/* Right — browser mockup */}
        <motion.div
          style={{ rotate: browserRotate, y: browserY }}
          className="relative flex items-center justify-center"
        >
          <BrowserMockup />
        </motion.div>
      </motion.div>
    </section>
  );
}

function BrowserMockup() {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.94, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 1.1, ease, delay: 0.2 }}
      className="animate-float-slow relative w-full max-w-[620px]"
    >
      <div
        className="glass-strong overflow-hidden rounded-2xl"
        style={{ boxShadow: "0 40px 120px -30px var(--glow), 0 0 0 1px var(--border)" }}
      >
        {/* chrome */}
        <div className="flex items-center gap-2 border-b border-border px-4 py-3">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-foreground/20" />
            <span className="h-2.5 w-2.5 rounded-full bg-foreground/20" />
            <span className="h-2.5 w-2.5 rounded-full bg-foreground/20" />
          </div>
          <div className="mx-auto flex items-center gap-2 rounded-md bg-foreground/[0.04] px-3 py-1 text-[11px] text-muted-foreground">
            <Lock className="h-3 w-3" /> sentinel.ai/scan/prod-app
          </div>
        </div>

        {/* body */}
        <div className="grid grid-cols-[1fr_1.1fr] gap-3 p-4">
          {/* left — AI reasoning */}
          <div className="rounded-lg border border-border bg-foreground/[0.02] p-3">
            <div className="mb-3 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[10px] font-medium text-muted-foreground">
                <Sparkles className="h-3 w-3 text-primary" /> AI Reasoning
              </span>
              <span className="text-[10px] text-primary">live</span>
            </div>
            <div className="space-y-2">
              {[
                "Fingerprinting stack…",
                "React 19 · Vite · Cloud",
                "Crawling routes /login /api",
                "Header CSP: weak default",
                "Storage: token in localStorage",
                "Generating remediation…",
              ].map((t, i) => (
                <motion.div
                  key={t}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.6 + i * 0.35, duration: 0.4 }}
                  className="flex items-center gap-2 text-[11px] text-foreground/80"
                >
                  <span className="h-1 w-1 rounded-full bg-primary" />
                  {t}
                </motion.div>
              ))}
            </div>
          </div>

          {/* right — score + chart + requests */}
          <div className="space-y-3">
            <div className="glass rounded-lg p-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-muted-foreground">Risk Score</span>
                <span className="text-[10px] text-primary">B+</span>
              </div>
              <div className="mt-2 flex items-end gap-1">
                <span className="text-3xl font-semibold tracking-tight">78</span>
                <span className="mb-1 text-[10px] text-muted-foreground">/100</span>
              </div>
              <ScoreBar />
            </div>

            <MiniChart />

            <div className="rounded-lg border border-border bg-foreground/[0.02] p-3">
              <span className="text-[10px] font-medium text-muted-foreground">Network</span>
              <div className="mt-2 space-y-1.5">
                {[
                  { m: "GET", u: "/api/user", s: 200 },
                  { m: "POST", u: "/api/auth", s: 401 },
                  { m: "GET", u: "/env.js", s: 200, warn: true },
                ].map((r, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 1 + i * 0.3 }}
                    className="flex items-center justify-between font-mono text-[10px]"
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="rounded bg-foreground/10 px-1 py-0.5 text-[9px]">{r.m}</span>
                      <span className={r.warn ? "text-primary" : "text-foreground/70"}>{r.u}</span>
                    </span>
                    <span className={r.s === 200 ? "text-emerald-400/80" : "text-primary"}>
                      {r.s}
                    </span>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
      {/* reflection glow */}
      <div
        aria-hidden
        className="absolute -inset-x-10 -bottom-10 h-40 rounded-full opacity-60 blur-3xl"
        style={{ background: "radial-gradient(ellipse, var(--glow), transparent 70%)" }}
      />
    </motion.div>
  );
}

function ScoreBar() {
  return (
    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-foreground/10">
      <motion.div
        initial={{ width: 0 }}
        whileInView={{ width: "78%" }}
        viewport={{ once: true }}
        transition={{ duration: 1.4, ease, delay: 0.4 }}
        className="h-full rounded-full"
        style={{ background: "linear-gradient(90deg, var(--primary), var(--accent))" }}
      />
    </div>
  );
}

function MiniChart() {
  const pts = [22, 40, 30, 55, 45, 68, 60, 78, 72, 88];
  const d = pts
    .map((p, i) => `${i === 0 ? "M" : "L"} ${(i / (pts.length - 1)) * 100} ${100 - p}`)
    .join(" ");
  return (
    <div className="rounded-lg border border-border bg-foreground/[0.02] p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[10px] font-medium text-muted-foreground">Coverage</span>
        <span className="text-[10px] text-primary">+24%</span>
      </div>
      <svg viewBox="0 0 100 60" className="h-14 w-full" preserveAspectRatio="none">
        <defs>
          <linearGradient id="grad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <motion.path
          d={`${d} L 100 60 L 0 60 Z`}
          fill="url(#grad)"
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 1 }}
        />
        <motion.path
          d={d}
          fill="none"
          stroke="var(--primary)"
          strokeWidth="1.5"
          initial={{ pathLength: 0 }}
          whileInView={{ pathLength: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 1.4, ease }}
        />
      </svg>
    </div>
  );
}

/* -------------------- MARQUEE -------------------- */

const brands = [
  "ORION",
  "HELIX",
  "NIMBUS",
  "VERTEX",
  "AURORA",
  "PARALLAX",
  "QUANTA",
  "PIXEL FORGE",
  "MERIDIAN",
  "OBSIDIAN",
];

function Marquee() {
  return (
    <section className="border-y border-border/60 py-10">
      <p className="mb-6 text-center text-xs uppercase tracking-[0.2em] text-muted-foreground">
        Trusted by security-first teams
      </p>
      <div className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-32 bg-gradient-to-r from-background to-transparent" />
        <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-32 bg-gradient-to-l from-background to-transparent" />
        <div className="animate-marquee flex w-max gap-16 whitespace-nowrap">
          {[...brands, ...brands].map((b, i) => (
            <span
              key={i}
              className="font-display text-xl font-semibold tracking-[0.2em] text-muted-foreground/60"
            >
              {b}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* -------------------- FEATURES -------------------- */

const features = [
  {
    icon: Eye,
    title: "AI Agent Exploration",
    desc: "Sentinel navigates your app like a human, discovering routes, forms and hidden endpoints.",
  },
  {
    icon: KeyRound,
    title: "Secrets Detection",
    desc: "Detects leaked API keys, tokens and credentials in bundles, storage and network traffic.",
  },
  {
    icon: Network,
    title: "Network Analysis",
    desc: "Inspects every request. Flags insecure endpoints, mixed content and CORS misconfigurations.",
  },
  {
    icon: Shield,
    title: "Security Headers",
    desc: "CSP, HSTS, X-Frame — graded against modern OWASP baselines with fix-it snippets.",
  },
  {
    icon: Cookie,
    title: "Cookie Inspection",
    desc: "Audits SameSite, HttpOnly, Secure flags and scope leakage across subdomains.",
  },
  {
    icon: Database,
    title: "Storage Audit",
    desc: "Scans localStorage, sessionStorage and IndexedDB for sensitive artifacts.",
  },
  {
    icon: FileText,
    title: "AI Report Generation",
    desc: "Delivers a prioritized, actionable PDF with remediation code — not a checklist.",
  },
  {
    icon: Zap,
    title: "Instant Insights",
    desc: "Full deep-scan of a production app in under 90 seconds. No agents. No installs.",
  },
];

function Features() {
  return (
    <section id="features" className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader
        eyebrow="Capabilities"
        title="An engineer that reads your app end-to-end."
        subtitle="Every layer of your web surface — inspected, reasoned about, and hardened."
      />
      <div className="mt-16 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {features.map((f, i) => (
          <motion.div key={f.title} {...fadeUp(i * 0.04)}>
            <SpotlightCard className="group relative h-full overflow-hidden rounded-2xl p-6">
              <div className="relative z-[1] mb-6 grid h-10 w-10 place-items-center rounded-xl bg-primary/10 text-primary ring-1 ring-primary/20 transition-transform duration-500 group-hover:scale-110 group-hover:rotate-3">
                <f.icon className="h-5 w-5" />
              </div>
              <h3 className="relative z-[1] mb-2 font-display text-base font-semibold tracking-tight">
                {f.title}
              </h3>
              <p className="relative z-[1] text-sm leading-relaxed text-muted-foreground">
                {f.desc}
              </p>
            </SpotlightCard>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* -------------------- HOW IT WORKS -------------------- */

const steps = [
  {
    n: "01",
    title: "Paste your URL",
    desc: "Any deployed web app. No agents, no SDK, no code changes.",
  },
  {
    n: "02",
    title: "AI launches a secure browser",
    desc: "Playwright fires up an isolated Chromium session in the cloud.",
  },
  {
    n: "03",
    title: "Explores like a human",
    desc: "Clicks, scrolls, submits forms. Maps your entire attack surface.",
  },
  {
    n: "04",
    title: "Analyzes every request",
    desc: "Every response, header, cookie and payload — all inspected.",
  },
  {
    n: "05",
    title: "Finds vulnerabilities",
    desc: "Correlates signals. Reasons about intent. Ranks by severity.",
  },
  {
    n: "06",
    title: "Generates the report",
    desc: "Actionable, prioritized, human-readable. Delivered instantly.",
  },
];

function HowItWorks() {
  return (
    <section id="how" className="relative mx-auto max-w-6xl px-6 py-32">
      <SectionHeader eyebrow="How it works" title="Six steps. Ninety seconds." />
      <div className="relative mt-20">
        <div
          aria-hidden
          className="absolute left-[27px] top-0 h-full w-px bg-gradient-to-b from-transparent via-primary/40 to-transparent md:left-1/2"
        />
        {steps.map((s, i) => (
          <motion.div
            key={s.n}
            {...fadeUp(i * 0.05)}
            className={`relative mb-10 flex flex-col gap-4 md:mb-16 md:flex-row md:items-center ${
              i % 2 === 0 ? "" : "md:flex-row-reverse"
            }`}
          >
            <div
              className={`flex items-center gap-4 md:w-1/2 ${i % 2 === 0 ? "md:justify-end md:pr-12" : "md:justify-start md:pl-12"}`}
            >
              <div
                className={`glass grow rounded-2xl p-5 ${i % 2 === 0 ? "md:text-right" : "md:text-left"}`}
              >
                <span className="mb-1 block font-mono text-xs text-primary">{s.n}</span>
                <h3 className="mb-1 font-display text-lg font-semibold tracking-tight">
                  {s.title}
                </h3>
                <p className="text-sm text-muted-foreground">{s.desc}</p>
              </div>
            </div>
            <div className="absolute left-0 top-4 md:left-1/2 md:top-1/2 md:-translate-x-1/2 md:-translate-y-1/2">
              <div className="glass grid h-14 w-14 place-items-center rounded-full ring-1 ring-primary/40">
                <span className="font-mono text-xs text-primary">{s.n}</span>
              </div>
            </div>
            <div className="hidden md:block md:w-1/2" />
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* -------------------- INTERACTIVE DEMO -------------------- */

function InteractiveDemo() {
  const [url, setUrl] = useState("https://example.com");
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<{ t: string; kind: "info" | "warn" | "ok" }[]>([]);
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);

  const script: { t: string; kind: "info" | "warn" | "ok" }[] = [
    { t: "Launching secure browser…", kind: "info" },
    { t: "Fingerprinting stack: React 19 · Vite", kind: "info" },
    { t: "Crawling routes (12 discovered)", kind: "info" },
    { t: "Analyzing 84 network requests", kind: "info" },
    { t: "Missing CSP header on 3 routes", kind: "warn" },
    { t: "Token found in localStorage (auth-token)", kind: "warn" },
    { t: "HSTS enabled · TLS 1.3 verified", kind: "ok" },
    { t: "2 exposed secrets in bundle.js", kind: "warn" },
    { t: "Generating AI report…", kind: "info" },
    { t: "Scan complete — score 78/100", kind: "ok" },
  ];

  const start = () => {
    if (running) return;
    setRunning(true);
    setDone(false);
    setLogs([]);
    setProgress(0);
    script.forEach((line, i) => {
      setTimeout(
        () => {
          setLogs((prev) => [...prev, line]);
          setProgress(((i + 1) / script.length) * 100);
          if (i === script.length - 1) {
            setDone(true);
            setRunning(false);
          }
        },
        500 + i * 550,
      );
    });
  };

  return (
    <section id="demo" className="relative mx-auto max-w-6xl px-6 py-32">
      <SectionHeader
        eyebrow="Live Demo"
        title="Try it. It's real-time."
        subtitle="A simulated scan against any URL — see how Sentinel reasons."
      />

      <motion.div {...fadeUp(0.1)} className="glass-strong mt-14 overflow-hidden rounded-3xl">
        <div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center">
          <div className="glass flex flex-1 items-center gap-3 rounded-full px-4 py-2.5">
            <Lock className="h-4 w-4 text-muted-foreground" />
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              placeholder="https://your-app.com"
              spellCheck={false}
            />
          </div>
          <button
            onClick={start}
            disabled={running}
            className="inline-flex items-center justify-center gap-2 rounded-full bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition hover:brightness-110 disabled:opacity-60"
            style={{ boxShadow: "0 12px 30px -12px var(--glow)" }}
          >
            {running ? "Scanning…" : "Analyze"}
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>

        <div className="h-1 w-full bg-foreground/[0.06]">
          <motion.div
            animate={{ width: `${progress}%` }}
            transition={{ ease }}
            className="h-full"
            style={{ background: "linear-gradient(90deg, var(--primary), var(--accent))" }}
          />
        </div>

        <div className="grid gap-4 p-4 sm:grid-cols-3">
          <Stat label="Requests" value={Math.floor((progress / 100) * 84)} />
          <Stat label="Secrets" value={progress > 60 ? 2 : 0} accent />
          <Stat label="Headers OK" value={progress > 40 ? 7 : 0} />
        </div>

        <div className="max-h-72 overflow-hidden border-t border-border bg-foreground/[0.02] p-4 font-mono text-xs">
          <AnimatePresence initial={false}>
            {logs.map((l, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
                className="flex items-center gap-2 py-1"
              >
                <span
                  className={
                    l.kind === "warn"
                      ? "text-primary"
                      : l.kind === "ok"
                        ? "text-emerald-400/80"
                        : "text-muted-foreground"
                  }
                >
                  {l.kind === "warn" ? "!" : l.kind === "ok" ? "✓" : "›"}
                </span>
                <span className="text-foreground/80">{l.t}</span>
              </motion.div>
            ))}
            {!logs.length && <div className="text-muted-foreground/60">Waiting to start scan…</div>}
          </AnimatePresence>
        </div>

        {done && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-between border-t border-border p-4"
          >
            <div>
              <span className="text-xs text-muted-foreground">Final Report</span>
              <div className="mt-0.5 flex items-baseline gap-2">
                <span className="font-display text-2xl font-semibold">78/100</span>
                <span className="text-xs text-primary">Grade B+</span>
              </div>
            </div>
            <button className="glass rounded-full px-4 py-2 text-xs">Download PDF</button>
          </motion.div>
        )}
      </motion.div>
    </section>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="glass rounded-xl p-4">
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      <div
        className={`mt-1 font-display text-2xl font-semibold tabular-nums ${accent ? "text-primary" : ""}`}
      >
        {value}
      </div>
    </div>
  );
}

/* -------------------- ARCHITECTURE -------------------- */

const arch = [
  { title: "Browser", desc: "User's URL enters the pipeline." },
  { title: "Playwright", desc: "Headless Chromium in an isolated sandbox." },
  { title: "Security Engine", desc: "Parsers for headers, storage, network." },
  { title: "AI Reasoning", desc: "LLM correlates and prioritizes signals." },
  { title: "Report", desc: "Delivered as PDF, JSON or webhook." },
];

function Architecture() {
  return (
    <section id="architecture" className="relative mx-auto max-w-6xl px-6 py-32">
      <SectionHeader eyebrow="Architecture" title="Autonomous. Isolated. Explainable." />
      <div className="mt-16 grid gap-4 md:grid-cols-5">
        {arch.map((a, i) => (
          <motion.div key={a.title} {...fadeUp(i * 0.06)} className="relative">
            <div className="glass rounded-2xl p-5">
              <div className="mb-3 font-mono text-[10px] text-primary">0{i + 1}</div>
              <h4 className="mb-1 font-display text-sm font-semibold">{a.title}</h4>
              <p className="text-xs leading-relaxed text-muted-foreground">{a.desc}</p>
            </div>
            {i < arch.length - 1 && (
              <div className="pointer-events-none absolute -right-2 top-1/2 hidden -translate-y-1/2 md:block">
                <motion.div
                  initial={{ opacity: 0, x: -4 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.2 + i * 0.1 }}
                  className="h-px w-6 bg-primary/60"
                />
              </div>
            )}
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* -------------------- ROADMAP -------------------- */

const roadmap = [
  { icon: GitBranch, title: "CI/CD Integration" },
  { icon: Chrome, title: "Browser Extension" },
  { icon: Bell, title: "Slack Alerts" },
  { icon: Github, title: "GitHub Integration" },
  { icon: Users, title: "Team Workspace" },
  { icon: Radar, title: "Attack Simulation" },
  { icon: FileText, title: "PDF Reports" },
  { icon: Zap, title: "Public API" },
  { icon: Shield, title: "Enterprise SSO" },
];

function Roadmap() {
  return (
    <section id="roadmap" className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader
        eyebrow="Roadmap"
        title="Shipping soon."
        subtitle="What's next on the Sentinel schedule."
      />
      <div className="mt-16 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {roadmap.map((r, i) => (
          <motion.div key={r.title} {...fadeUp(i * 0.03)}>
            <SpotlightCard className="flex items-center gap-4 rounded-2xl p-5">
              <div className="grid h-10 w-10 place-items-center rounded-xl bg-foreground/[0.04] text-primary transition-transform duration-500 hover:rotate-6">
                <r.icon className="h-4 w-4" />
              </div>
              <div className="flex-1">
                <h4 className="font-display text-sm font-semibold">{r.title}</h4>
                <span className="text-xs text-muted-foreground">Coming soon</span>
              </div>
              <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] text-primary">
                Q3
              </span>
            </SpotlightCard>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* -------------------- TESTIMONIALS -------------------- */

const testimonials = [
  {
    q: "It found three exposed keys in our production bundle within 40 seconds. We shipped the fix the same day.",
    a: "Kai Ferrera",
    role: "Staff Engineer, Helix",
  },
  {
    q: "Sentinel doesn't dump a checklist — it explains why something matters. That's a first for us.",
    a: "Priya Ranjan",
    role: "Head of Security, Meridian",
  },
  {
    q: "We replaced two vendors with Sentinel. The AI reasoning is genuinely useful.",
    a: "Ben Ostrowski",
    role: "CTO, Obsidian Labs",
  },
];

function Testimonials() {
  return (
    <section className="relative mx-auto max-w-7xl px-6 py-32">
      <SectionHeader eyebrow="Reception" title="Teams that ship fast, trust Sentinel." />
      <div className="mt-14 grid gap-4 md:grid-cols-3">
        {testimonials.map((t, i) => (
          <motion.figure
            key={i}
            {...fadeUp(i * 0.06)}
            className="glass flex h-full flex-col justify-between rounded-2xl p-6"
          >
            <blockquote className="text-sm leading-relaxed text-foreground/90">"{t.q}"</blockquote>
            <figcaption className="mt-6 text-xs">
              <div className="font-medium text-foreground">{t.a}</div>
              <div className="text-muted-foreground">{t.role}</div>
            </figcaption>
          </motion.figure>
        ))}
      </div>
    </section>
  );
}

/* -------------------- PRICING -------------------- */

function Pricing() {
  const inc = [
    "Unlimited scans while in beta",
    "AI reasoning + reports",
    "Secrets & header analysis",
    "Cookie + storage audit",
    "Priority Discord support",
  ];
  return (
    <section id="pricing" className="relative mx-auto max-w-4xl px-6 py-32">
      <SectionHeader eyebrow="Pricing" title="One plan. Free during beta." />
      <motion.div
        {...fadeUp(0.05)}
        className="glass-strong relative mx-auto mt-14 max-w-md overflow-hidden rounded-3xl p-8"
        style={{ boxShadow: "0 40px 100px -30px var(--glow), 0 0 0 1px var(--border)" }}
      >
        <div
          aria-hidden
          className="pointer-events-none absolute -top-24 left-1/2 h-48 w-64 -translate-x-1/2 opacity-70 blur-3xl"
          style={{ background: "radial-gradient(ellipse, var(--glow), transparent 70%)" }}
        />
        <span className="text-xs uppercase tracking-widest text-primary">Free Beta</span>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="font-display text-5xl font-semibold">$0</span>
          <span className="text-sm text-muted-foreground">/ forever during beta</span>
        </div>
        <p className="mt-3 text-sm text-muted-foreground">
          All features. No credit card. No limits while we're in beta.
        </p>
        <ul className="mt-8 space-y-3 text-sm">
          {inc.map((i) => (
            <li key={i} className="flex items-center gap-3">
              <span className="grid h-5 w-5 place-items-center rounded-full bg-primary/15 text-primary">
                <Check className="h-3 w-3" />
              </span>
              <span className="text-foreground/85">{i}</span>
            </li>
          ))}
        </ul>
        <a
          href="#demo"
          className="mt-10 inline-flex w-full items-center justify-center gap-2 rounded-full bg-primary px-6 py-3 text-sm font-medium text-primary-foreground transition hover:brightness-110"
        >
          Get early access <ArrowRight className="h-4 w-4" />
        </a>
        <p className="mt-4 text-center text-xs text-muted-foreground">
          Teams, SSO and enterprise — <span className="text-primary">coming soon</span>.
        </p>
      </motion.div>
    </section>
  );
}

/* -------------------- FAQ -------------------- */

const faq = [
  {
    q: "How is Sentinel different from a traditional scanner?",
    a: "Traditional scanners run signature-based checks and dump a checklist. Sentinel uses an autonomous AI agent to explore your app like a human, reason about your specific stack, and produce contextual, prioritized recommendations.",
  },
  {
    q: "Do I need to install anything?",
    a: "No. Sentinel operates from the outside using a headless browser. Paste your URL — nothing to install, no agents, no SDK.",
  },
  {
    q: "Is my data stored?",
    a: "No. Scans run in isolated sandboxes. Reports are retained only for your session unless you explicitly export them.",
  },
  {
    q: "Can it scan authenticated pages?",
    a: "Authenticated scans are on the roadmap for our team-tier release later this year.",
  },
  {
    q: "Which frameworks are supported?",
    a: "Any deployed web app — React, Vue, Svelte, Next, Remix, static sites. If it renders in a browser, Sentinel can inspect it.",
  },
];

function FAQ() {
  return (
    <section className="relative mx-auto max-w-3xl px-6 py-32">
      <SectionHeader eyebrow="FAQ" title="Answers, briefly." />
      <div className="mt-12">
        <Accordion type="single" collapsible className="space-y-3">
          {faq.map((f, i) => (
            <AccordionItem
              key={i}
              value={`i-${i}`}
              className="glass overflow-hidden rounded-2xl border-0 px-5"
            >
              <AccordionTrigger className="py-5 text-left text-sm font-medium hover:no-underline">
                {f.q}
              </AccordionTrigger>
              <AccordionContent className="pb-5 text-sm leading-relaxed text-muted-foreground">
                {f.a}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </section>
  );
}

/* -------------------- FOOTER -------------------- */

function Footer() {
  return (
    <footer className="relative mx-auto mt-16 max-w-7xl px-6 py-16">
      <div className="glass rounded-3xl p-10">
        <div className="flex flex-col items-start justify-between gap-8 md:flex-row md:items-center">
          <div>
            <div className="flex items-center gap-2 font-semibold">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
                <Shield className="h-4 w-4" />
              </span>
              Sentinel<span className="text-primary">.AI</span>
            </div>
            <p className="mt-3 max-w-sm text-sm text-muted-foreground">
              Autonomous AI security engineer for the modern web. Built for developers who ship.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-8 text-sm sm:grid-cols-4">
            {[
              { h: "Product", l: ["Features", "Pricing", "Roadmap"] },
              { h: "Company", l: ["About", "Blog", "Contact"] },
              { h: "Legal", l: ["Privacy", "Terms", "Security"] },
              { h: "Connect", l: ["GitHub", "X / Twitter", "Docs"] },
            ].map((c) => (
              <div key={c.h}>
                <div className="mb-3 text-xs uppercase tracking-widest text-muted-foreground">
                  {c.h}
                </div>
                <ul className="space-y-2">
                  {c.l.map((x) => (
                    <li key={x}>
                      <a href="#" className="text-foreground/70 transition hover:text-foreground">
                        {x}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-10 flex flex-col items-start justify-between gap-4 border-t border-border pt-6 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <span>© {new Date().getFullYear()} Sentinel AI. All rights reserved.</span>
          <div className="flex items-center gap-4">
            <span>Crafted with precision.</span>
            <ThemeToggle />
          </div>
        </div>
      </div>
    </footer>
  );
}

/* -------------------- SECTION HEADER -------------------- */

function SectionHeader({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <motion.span {...fadeUp(0)} className="text-xs uppercase tracking-[0.25em] text-primary">
        {eyebrow}
      </motion.span>
      <motion.h2
        {...fadeUp(0.05)}
        className="text-balance mt-4 font-display text-4xl font-semibold leading-[1.05] tracking-tight sm:text-5xl"
      >
        <span className="text-gradient">{title}</span>
      </motion.h2>
      {subtitle && (
        <motion.p {...fadeUp(0.1)} className="mt-4 text-balance text-base text-muted-foreground">
          {subtitle}
        </motion.p>
      )}
    </div>
  );
}

/* -------------------- LANDING -------------------- */

function Landing() {
  return (
    <div className="relative">
      <Background />
      <ScrollProgress />
      <Nav />
      <main>
        <Hero />
        <Marquee />
        <Features />
        <HowItWorks />
        <InteractiveDemo />
        <Architecture />
        <Roadmap />
        <Testimonials />
        <Pricing />
        <FAQ />
      </main>
      <Footer />
    </div>
  );
}
