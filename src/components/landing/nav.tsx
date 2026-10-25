import { motion, useScroll, useTransform } from "motion/react";
import { Shield, LayoutDashboard } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";
import { Link, useRouterState } from "@tanstack/react-router";

const landingLinks = [
  { label: "Features", href: "#features" },
  { label: "How it Works", href: "#how" },
  { label: "Architecture", href: "#architecture" },
  { label: "Roadmap", href: "#roadmap" },
  { label: "Pricing", href: "#pricing" },
];

export function Nav() {
  const { scrollY } = useScroll();
  const blur = useTransform(scrollY, [0, 200], [8, 20]);
  const border = useTransform(scrollY, [0, 200], [0, 1]);
  const routerState = useRouterState();
  const isLanding = routerState.location.pathname === "/";

  return (
    <motion.nav
      style={{
        backdropFilter: useTransform(blur, (v: number) => `blur(${v}px) saturate(160%)`),
      }}
      className="fixed inset-x-0 top-0 z-50"
    >
      <motion.div
        style={{ opacity: border }}
        className="absolute inset-x-0 bottom-0 h-px bg-border"
      />
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
            <Shield className="h-4 w-4" />
          </span>
          <span>
            Sentinel<span className="text-primary">.AI</span>
          </span>
        </Link>

        <div className="hidden items-center gap-8 md:flex">
          {isLanding ? (
            <>
              {landingLinks.map((l) => (
                <a
                  key={l.href}
                  href={l.href}
                  className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                >
                  {l.label}
                </a>
              ))}
            </>
          ) : (
            <>
              <Link
                to="/scan"
                className="text-sm text-muted-foreground transition-colors hover:text-foreground [&.active]:text-foreground"
              >
                Scanner
              </Link>
              <Link
                to="/dashboard"
                className="text-sm text-muted-foreground transition-colors hover:text-foreground [&.active]:text-foreground"
              >
                Dashboard
              </Link>
            </>
          )}
        </div>

        <div className="flex items-center gap-2">
          <ThemeToggle />
          {!isLanding && (
            <Link
              to="/dashboard"
              className="glass hidden items-center gap-2 rounded-full px-4 py-2 text-sm transition hover:scale-[1.01] sm:inline-flex"
            >
              <LayoutDashboard className="h-3.5 w-3.5" /> Dashboard
            </Link>
          )}
          <Link
            to="/scan"
            className="hidden rounded-full bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow-[0_0_0_1px_var(--border),0_10px_30px_-10px_var(--glow)] transition hover:brightness-110 sm:inline-flex"
          >
            Start Scan
          </Link>
        </div>
      </div>
    </motion.nav>
  );
}
