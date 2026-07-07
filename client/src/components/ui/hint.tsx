import { cn } from "@/lib/utils";

/**
 * Hint — the single, shared hover-tooltip used across the app (icon strip + header
 * actions), so every button gets the same styled pill instead of the browser's native
 * `title` OS tooltip. Wrap a button:
 *
 *   <Hint label="New scan" side="bottom"><button>…</button></Hint>
 *
 * Hover-only (no touch), pointer-events-none, matches the original strip tooltip styling.
 */
type HintSide = "right" | "left" | "top" | "bottom" | "bottom-end";

// Position of the bubble relative to the wrapped element.
const SIDE_POS: Record<HintSide, string> = {
  right: "left-full ml-2 top-1/2 -translate-y-1/2",
  left: "right-full mr-2 top-1/2 -translate-y-1/2",
  top: "bottom-full mb-2 left-1/2 -translate-x-1/2",
  bottom: "top-full mt-2 left-1/2 -translate-x-1/2",
  // Right-aligned drop — for buttons near the viewport's right edge so the pill
  // never clips off-screen.
  "bottom-end": "top-full mt-2 right-0",
};

export function Hint({
  label,
  side = "right",
  className,
  children,
}: {
  label: string;
  side?: HintSide;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("group relative inline-flex", className)}>
      {children}
      <div
        className={cn(
          "absolute z-[80] pointer-events-none hidden group-hover:block",
          SIDE_POS[side],
        )}
      >
        <div className="px-2.5 py-1.5 bg-neutral-900 text-white text-xs font-medium rounded-lg whitespace-nowrap shadow-xl border border-white/10">
          {label}
        </div>
      </div>
    </div>
  );
}
