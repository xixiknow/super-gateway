import { useEffect, useState } from "react";

/** 1 Hz countdown until an ISO timestamp; flips inactive once the deadline passes. */
export function useCountdown(until: string | null | undefined): { active: boolean; secondsLeft: number } {
  const deadline = typeof until === "string" && !Number.isNaN(Date.parse(until)) ? Date.parse(until) : null;
  const compute = () => (deadline === null ? 0 : Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
  const [secondsLeft, setSecondsLeft] = useState(compute);
  useEffect(() => {
    setSecondsLeft(compute());
    if (deadline === null) return;
    const timer = window.setInterval(() => setSecondsLeft(compute()), 1_000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deadline]);
  return { active: deadline !== null && secondsLeft > 0, secondsLeft };
}

/** Utilization bar with teal (<70%) / amber (<90%) / coral (≥90%) thresholds. */
export function Meter({ label, value, note }: { label: string; value: number | null; note?: string }) {
  const percent = value == null ? null : Math.round(Math.min(1, Math.max(0, value)) * 100);
  const tone = percent == null ? "empty" : percent >= 90 ? "coral" : percent >= 70 ? "amber" : "teal";
  return <div className={`meter meter-${tone}`} role="img" aria-label={`${label} ${percent ?? "—"}%`}>
    <div className="meter-head"><span>{label}</span><span className="mono">{percent == null ? "—" : `${percent}%`}</span></div>
    <div className="meter-track"><div className="meter-fill" style={{ width: `${percent ?? 0}%` }} /></div>
    {note && <div className="meter-note">{note}</div>}
  </div>;
}
