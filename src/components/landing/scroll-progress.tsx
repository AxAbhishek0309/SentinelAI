import { motion, useScroll, useSpring } from "motion/react";

export function ScrollProgress() {
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 24,
    mass: 0.3,
  });
  return (
    <motion.div
      aria-hidden
      style={{
        scaleX,
        transformOrigin: "0% 50%",
        background: "linear-gradient(90deg, var(--primary), var(--accent))",
      }}
      className="fixed inset-x-0 top-0 z-[60] h-[2px] opacity-90"
    />
  );
}
