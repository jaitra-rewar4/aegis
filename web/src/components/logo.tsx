/**
 * logo.tsx — the Aegis mark and wordmark.
 *
 * The mark is a shield (aegis means shield) cut by a vertical gate line, with a single
 * decision node where the line meets the centre: protection, a boundary, and the point where
 * the verdict is made. Monoline, drawn in currentColor so it inherits the surrounding text
 * colour and stays monochrome on the page.
 */

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <g
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 2.8 L19.6 5.7 L19.6 11.9 C19.6 16.6 16.1 19.9 12 21.6 C7.9 19.9 4.4 16.6 4.4 11.9 L4.4 5.7 Z" />
        <path d="M12 6.9 L12 10.2" />
        <path d="M12 13.8 L12 17.1" />
      </g>
      <rect
        x="10.3"
        y="10.3"
        width="3.4"
        height="3.4"
        rx="0.5"
        transform="rotate(45 12 12)"
        fill="currentColor"
      />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 ${className ?? ""}`}>
      <LogoMark className="size-[1.25em]" />
      <span className="font-display text-lg font-bold tracking-tight">Aegis</span>
    </span>
  );
}
