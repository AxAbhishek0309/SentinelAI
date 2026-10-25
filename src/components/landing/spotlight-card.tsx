import { useRef, type ReactNode, type MouseEvent } from "react";

type Props = {
  children: ReactNode;
  className?: string;
};

/**
 * Card wrapper that follows the cursor with a soft radial highlight
 * via CSS vars --mx / --my, consumed by the `spotlight` utility.
 */
export function SpotlightCard({ children, className = "" }: Props) {
  const ref = useRef<HTMLDivElement>(null);

  const onMove = (e: MouseEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 100;
    const y = ((e.clientY - rect.top) / rect.height) * 100;
    el.style.setProperty("--mx", `${x}%`);
    el.style.setProperty("--my", `${y}%`);
  };

  return (
    <div ref={ref} onMouseMove={onMove} className={`glass spotlight hover-lift ${className}`}>
      {children}
    </div>
  );
}
