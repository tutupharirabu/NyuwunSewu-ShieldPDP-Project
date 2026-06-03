import { KeyRound, Moon, Server, ShieldCheck, UserRound } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAuth } from "@/context/auth-context";
import { useTheme } from "@/context/theme-context";

export { SettingsPage as default };
export function SettingsPage() {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="grid gap-4 xl:grid-cols-[0.85fr_1.15fr]">
      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
          <CardDescription>
            Authenticated user and role context.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3 rounded-lg border bg-background p-4">
            <UserRound className="h-5 w-5 text-primary" />
            <div>
              <p className="font-medium">{user?.full_name}</p>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 rounded-lg border bg-background p-4">
            <ShieldCheck className="h-5 w-5 text-emerald-600" />
            <div>
              <p className="font-medium">{user?.role}</p>
              <p className="text-sm text-muted-foreground">
                Role-based permissions enforced by API
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Console Settings</CardTitle>
          <CardDescription>
            Frontend runtime configuration and permissions.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border bg-background p-4">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <p className="font-medium">API mode</p>
              </div>
              <p className="mt-2 text-sm text-muted-foreground">
                Vite proxy uses the local FastAPI backend during development.
              </p>
            </div>
            <div className="rounded-lg border bg-background p-4">
              <div className="flex items-center gap-2">
                <Moon className="h-4 w-4 text-muted-foreground" />
                <p className="font-medium">Appearance</p>
              </div>
              <div className="mt-3 flex items-center justify-between gap-3">
                <Badge variant="outline">{theme}</Badge>
                <Button variant="outline" size="sm" onClick={toggleTheme}>
                  Toggle
                </Button>
              </div>
            </div>
          </div>

          <div>
            <div className="mb-3 flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              <p className="font-medium">Permissions</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {user?.permissions.map((permission) => (
                <Badge key={permission} variant="secondary">
                  {permission}
                </Badge>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
