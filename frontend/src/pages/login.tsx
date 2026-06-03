import { FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/auth-context";

export function LoginPage() {
  const { isAuthenticated, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("admin@nyuwunsewu.local");
  const [password, setPassword] = useState("ChangeMe123!");
  const [organizationSlug, setOrganizationSlug] = useState("default-organization");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(email, password, organizationSlug);
      const state = location.state as { from?: { pathname?: string } } | null;
      navigate(state?.from?.pathname ?? "/dashboard", { replace: true });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to sign in");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-screen bg-background lg:grid-cols-[1fr_480px]">
      <section className="hidden border-r bg-card lg:flex lg:flex-col lg:justify-between">
        <div className="p-10">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-lg font-semibold">NS-Shield</p>
              <p className="text-sm text-muted-foreground">NyuwunSewu Shield</p>
            </div>
          </div>
          <div className="mt-20 max-w-xl">
            <p className="text-sm font-medium text-primary">Compliance-driven validation</p>
            <h1 className="mt-4 text-4xl font-semibold leading-tight">
              Security validation and privacy risk management for governed API estates.
            </h1>
            <p className="mt-5 text-base text-muted-foreground">
              Prioritize authorization risk, PII exposure, compliance impact, and remediation evidence without turning the console into a pentest tool wrapper.
            </p>
          </div>
        </div>
        <div className="border-t p-10 text-sm text-muted-foreground">
          Safe scan policies, tenant isolation, RBAC, audit logging, and evidence hashing are active by design.
        </div>
      </section>

      <main className="flex items-center justify-center p-6">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-xl">Sign in</CardTitle>
            <CardDescription>Use your NS-Shield organization account.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={handleSubmit}>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" value={email} onChange={(event) => setEmail(event.target.value)} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="organization">Organization slug</Label>
                <Input
                  id="organization"
                  value={organizationSlug}
                  onChange={(event) => setOrganizationSlug(event.target.value)}
                />
              </div>
              {error && (
                <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {error}
                </div>
              )}
              <Button className="w-full" type="submit" disabled={submitting}>
                {submitting ? "Signing in..." : "Sign in"}
              </Button>
            </form>
          </CardContent>
            </Card>
          </div>
        );
      }

      export { LoginPage as default };
