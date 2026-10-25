import { motion, useScroll, useTransform } from "motion/react";

export function Background() {
  const { scrollY } = useScroll();
  const y = useTransform(scrollY, [0, 800], [0, -200]);
  const y2 = useTransform(scrollY, [0, 1200], [0, 300]);

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      {/* base */}
      <div className="absolute inset-0 bg-background" />
      {/* grid */}
      <div className="grid-bg absolute inset-0 opacity-40" />
      {/* orange blob top-right */}
      <motion.div
        style={{ y }}
        className="absolute -right-40 -top-40 h-[560px] w-[560px] rounded-full"
      >
        <div
          className="h-full w-full rounded-full opacity-60 blur-[120px]"
          style={{
            background: "radial-gradient(circle, oklch(0.72 0.19 45 / 0.6), transparent 60%)",
          }}
        />
      </motion.div>
      {/* second blob bottom-left */}
      <motion.div
        style={{ y: y2 }}
        className="absolute -bottom-60 -left-40 h-[600px] w-[600px] rounded-full"
      >
        <div
          className="h-full w-full rounded-full opacity-40 blur-[140px]"
          style={{
            background: "radial-gradient(circle, oklch(0.8 0.16 65 / 0.5), transparent 60%)",
          }}
        />
      </motion.div>
      {/* particles */}
      <div className="absolute inset-0">
        {Array.from({ length: 22 }).map((_, i) => (
          <motion.span
            key={i}
            className="absolute h-1 w-1 rounded-full bg-foreground/30"
            style={{
              left: `${(i * 37) % 100}%`,
              top: `${(i * 53) % 100}%`,
            }}
            animate={{
              y: [0, -20, 0],
              opacity: [0.15, 0.6, 0.15],
            }}
            transition={{
              duration: 5 + (i % 5),
              repeat: Infinity,
              delay: i * 0.2,
              ease: "easeInOut",
            }}
          />
        ))}
      </div>
      {/* noise */}
      <div className="noise absolute inset-0 opacity-[0.08] mix-blend-overlay" />
      {/* vignette */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-background/80" />
    </div>
  );
}
