import type { StoreApp } from "@/lib/types";

const sizeMap = {
  sm: "h-12 w-12 text-[17px]",
  md: "h-[64px] w-[64px] text-[24px]",
  lg: "h-[88px] w-[88px] text-[34px]",
  xl: "h-[118px] w-[118px] text-[46px]",
} as const;

export function AppIcon({
  app,
  size = "md",
  className = "",
}: {
  app: Pick<StoreApp, "name" | "iconHue" | "kind" | "category"> & {
    iconUrl?: string;
  };
  size?: keyof typeof sizeMap;
  className?: string;
}) {
  const letter = app.name.trim().slice(0, 1).toUpperCase() || "A";
  const hue = app.iconHue;

  if (app.iconUrl) {
    return (
      <div
        className={`app-icon relative shrink-0 overflow-hidden ${sizeMap[size]} ${className}`}
        aria-hidden
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src={app.iconUrl}
          alt=""
          className="h-full w-full object-cover"
        />
      </div>
    );
  }

  return (
    <div
      className={`app-icon relative grid shrink-0 place-items-center overflow-hidden font-bold tracking-[-0.04em] text-white ${sizeMap[size]} ${className}`}
      style={{
        background: `
          radial-gradient(120% 90% at 18% 12%, rgba(255,255,255,0.38), transparent 42%),
          radial-gradient(80% 70% at 85% 90%, rgba(0,0,0,0.22), transparent 50%),
          linear-gradient(
            155deg,
            hsl(${hue} 62% 58%) 0%,
            hsl(${(hue + 18) % 360} 54% 42%) 48%,
            hsl(${(hue + 36) % 360} 48% 30%) 100%
          )
        `,
      }}
      aria-hidden
    >
      <span
        className="pointer-events-none absolute inset-0 opacity-[0.14]"
        style={{
          backgroundImage:
            "radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)",
          backgroundSize: "10px 10px",
        }}
      />
      <span className="relative z-[1] drop-shadow-[0_1px_1px_rgba(0,0,0,0.2)]">
        {letter}
      </span>
    </div>
  );
}
