import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  tone?: "default" | "danger" | "warning" | "success" | "info";
  detail?: string;
}

const tones = {
  default: "bg-primary/10 text-primary",
  danger: "bg-destructive/10 text-destructive",
  warning: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
  success: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  info: "bg-blue-500/10 text-blue-700 dark:text-blue-300"
};

export function MetricCard({ title, value, icon: Icon, tone = "default", detail }: MetricCardProps) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="mt-2 text-3xl font-semibold">{value}</p>
            {detail && <p className="mt-2 text-xs text-muted-foreground">{detail}</p>}
          </div>
          <div className={cn("rounded-md p-2", tones[tone])}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
