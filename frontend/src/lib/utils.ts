import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(value: number | null | undefined) {
  return new Intl.NumberFormat("en-US").format(value ?? 0);
}

function parseApiDate(value: string) {
  const includesZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  return new Date(includesZone ? value : `${value}Z`);
}

export function apiDateTimestamp(value: string) {
  return parseApiDate(value).getTime();
}

function localTimeZoneLabel(date: Date) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const indonesianZones: Record<string, string> = {
    "Asia/Jakarta": "WIB",
    "Asia/Pontianak": "WIB",
    "Asia/Makassar": "WITA",
    "Asia/Jayapura": "WIT"
  };
  if (indonesianZones[zone]) return indonesianZones[zone];
  return (
    new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
      .formatToParts(date)
      .find((part) => part.type === "timeZoneName")?.value ?? zone
  );
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "Not recorded";
  const date = parseApiDate(value);
  const timestamp = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  }).format(date);
  return `${timestamp} ${localTimeZoneLabel(date)}`;
}

export function formatRelativeTime(value: string | null | undefined, now = Date.now()) {
  if (!value) return "Not recorded";
  const deltaSeconds = Math.round((parseApiDate(value).getTime() - now) / 1000);
  const absoluteSeconds = Math.abs(deltaSeconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absoluteSeconds < 45) return "Just now";
  if (absoluteSeconds < 3600) return formatter.format(Math.round(deltaSeconds / 60), "minute");
  if (absoluteSeconds < 86400) return formatter.format(Math.round(deltaSeconds / 3600), "hour");
  if (absoluteSeconds < 604800) return formatter.format(Math.round(deltaSeconds / 86400), "day");
  return formatter.format(Math.round(deltaSeconds / 604800), "week");
}

export function compactId(value: string | null | undefined) {
  if (!value) return "-";
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}

export function severityColor(severity: string) {
  const normalized = severity.toLowerCase();
  if (normalized === "critical") return "destructive";
  if (normalized === "high") return "amber";
  if (normalized === "medium") return "blue";
  if (normalized === "low") return "emerald";
  return "secondary";
}
