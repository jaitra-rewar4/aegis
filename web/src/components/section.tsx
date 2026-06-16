import type { ReactNode } from "react";

/**
 * Section — the page's structural spine. Every content section is a "record field": a
 * sticky left rail carrying §0n + a mono label, and a right content column. This one grid,
 * shared by every section, is what turns a stack of centred cards into a single instrument —
 * and it fills the previously-empty right half of the max-w-6xl container.
 *
 * The rail is NOT a motion element (a lingering transform would break position: sticky), so
 * it's plain markup; section content animates via its own <Reveal> wrappers.
 */
export function Section({
  index,
  label,
  id,
  children,
}: {
  index: string;
  label: string;
  id?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="relative border-t border-line">
      <div className="mx-auto grid max-w-6xl grid-cols-1 gap-y-8 px-6 py-20 sm:py-24 lg:grid-cols-[180px_1fr] lg:gap-x-16">
        <div className="flex items-baseline gap-3 lg:sticky lg:top-28 lg:h-fit lg:flex-col lg:items-start lg:gap-2.5">
          <span className="font-mono text-[12px] tracking-[0.1em] text-paper">
            §{index}
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
            {label}
          </span>
        </div>
        <div className="min-w-0">{children}</div>
      </div>
    </section>
  );
}
