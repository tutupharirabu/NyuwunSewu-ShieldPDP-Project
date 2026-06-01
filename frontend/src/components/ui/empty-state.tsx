import { ShieldAlert } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

interface EmptyStateProps {
  title: string;
  description: string;
}

export function EmptyState({ title, description }: EmptyStateProps) {
  return (
    <Card>
      <CardContent className="flex min-h-44 flex-col items-center justify-center gap-3 text-center">
        <div className="rounded-md bg-muted p-3">
          <ShieldAlert className="h-5 w-5 text-muted-foreground" />
        </div>
        <div>
          <p className="font-medium">{title}</p>
          <p className="mt-1 max-w-md text-sm text-muted-foreground">{description}</p>
        </div>
      </CardContent>
    </Card>
  );
}

