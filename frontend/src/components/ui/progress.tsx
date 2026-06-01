import { cn } from "@/lib/utils";

interface ProgressProps {
  value: number;
  className?: string;
}

export function Progress({ value, className }: ProgressProps) {
  const bounded = Math.max(0, Math.min(100, value));
  return (
    <div className={cn("h-2 w-full overflow-hidden rounded-sm bg-muted", className)}>
      <div
        className="h-full rounded-sm bg-primary transition-all"
        style={{ width: `${bounded}%` }}
      />
    </div>
  );
}

