// One date format across TrustOps and LedgerSight (action items 16/11): "16 Nov 2026" and "16 Nov 2026, 14:05",
// in the viewer's local time. Accepts epoch seconds (the API), epoch milliseconds, ISO strings or Date objects.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n) => String(n).padStart(2, "0");

export function toDate(v) {
  if (v == null || v === "") return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === "number") return new Date(v < 1e11 ? v * 1000 : v);      // seconds vs milliseconds
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtDate(v, empty = "–") {
  const d = toDate(v);
  return d ? `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}` : empty;
}

export function fmtTime(v, empty = "–") {
  const d = toDate(v);
  return d ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : empty;
}

export function fmtDateTime(v, empty = "–") {
  const d = toDate(v);
  return d ? `${fmtDate(d)}, ${fmtTime(d)}` : empty;
}
