export function HeroScanVisual() {
  return (
    <div
      className="relative mx-auto aspect-[4/3] w-full max-w-lg overflow-hidden rounded-[2rem] bg-ink shadow-[var(--shadow)]"
      aria-hidden
    >
      <div
        className="absolute inset-0 opacity-90"
        style={{
          background:
            "radial-gradient(circle at 30% 20%, #1aa37f55, transparent 40%), radial-gradient(circle at 80% 70%, #b7791f33, transparent 35%), linear-gradient(160deg, #0b1f1a, #14352c)",
        }}
      />
      <div
        className="absolute inset-4 rounded-[1.4rem] border border-white/10"
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.06) 1px, transparent 1px)",
          backgroundSize: "28px 28px",
        }}
      />
      <div className="absolute inset-x-8 top-10 space-y-3 font-mono text-[11px] text-[#b7d7cb]">
        <p className="pulse-soft text-teal-bright">VIBE SCAN PIPELINE v1</p>
        <p>● ClamAV .............. CLEAN</p>
        <p>● ClamWin ............. CLEAN</p>
        <p>● VirusTotal .......... 0/70</p>
        <p>● VibeGuard ........... PASS</p>
        <p>● Entropy ............. 5.41</p>
        <p className="text-white/90">SECURITY SCORE ............ 97</p>
        <p className="text-teal-bright">READY FOR MASS RELEASE</p>
      </div>
      <div className="scan-beam absolute inset-x-4 h-16 bg-gradient-to-b from-teal-bright/0 via-teal-bright/35 to-teal-bright/0" />
      <div className="absolute bottom-6 left-6 right-6 flex items-end justify-between">
        <div className="rounded-lg bg-black/35 px-3 py-2 font-mono text-[10px] text-white/80 backdrop-blur">
          SHA256 · a1f9…c02e
        </div>
        <div className="grid h-14 w-14 place-items-center rounded-full bg-teal text-sm font-bold text-white">
          97
        </div>
      </div>
    </div>
  );
}
