import {
  Activity,
  BarChart3,
  Bot,
  ClipboardCheck,
  FileText,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  SearchCheck,
  Settings,
  ShieldCheck,
  Target,
  X
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { useAuth } from "@/context/auth-context";
import { cn } from "@/lib/utils";

const navigation = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Projects & Activity", href: "/projects", icon: FolderKanban },
  { name: "Targets", href: "/targets", icon: Target },
  { name: "Findings", href: "/findings", icon: SearchCheck },
  { name: "Agent Sessions", href: "/agent-sessions", icon: Bot },
  { name: "Compliance", href: "/compliance", icon: ClipboardCheck },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Remediation", href: "/remediation", icon: Activity },
  { name: "Settings", href: "/settings", icon: Settings }
];

const pageNames: Record<string, string> = {
  "/dashboard": "Executive Dashboard",
  "/projects": "Projects & Activity",
  "/targets": "Targets",
  "/findings": "Findings",
  "/agent-sessions": "Agent Sessions",
  "/compliance": "Compliance Intelligence",
  "/reports": "Reports",
  "/remediation": "Remediation",
  "/settings": "Settings",
  "/scan": "Create Scan"
};

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const title = location.pathname.startsWith("/scans/") ? "Scan Detail" : pageNames[location.pathname] ?? "NS-Shield";

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <div className="min-h-screen bg-background">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 border-r bg-card lg:block">
        <SidebarContent onNavigate={() => setMobileOpen(false)} />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-foreground/30" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 border-r bg-card shadow-enterprise">
            <div className="flex h-14 items-center justify-end px-3">
              <Button variant="ghost" size="icon" onClick={() => setMobileOpen(false)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 border-b bg-background/92 backdrop-blur">
          <div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
            <div className="flex items-center gap-3">
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                onClick={() => setMobileOpen(true)}
              >
                <Menu className="h-5 w-5" />
              </Button>
              <div>
                <h1 className="text-lg font-semibold">{title}</h1>
                <p className="hidden text-xs text-muted-foreground sm:block">
                  Compliance-driven validation and privacy risk management
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={() => navigate("/scan")}>
                <Radar className="h-4 w-4" />
                <span className="hidden sm:inline">New Scan</span>
              </Button>
              <ThemeToggle />
              <div className="hidden min-w-0 items-center gap-2 border-l pl-3 md:flex">
                <div className="min-w-0 text-right">
                  <p className="truncate text-sm font-medium">{user?.full_name}</p>
                  <p className="truncate text-xs text-muted-foreground">{user?.role}</p>
                </div>
                <Button variant="ghost" size="icon" onClick={handleLogout} aria-label="Sign out">
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </header>

        <main className="px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function SidebarContent({ onNavigate }: { onNavigate: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-16 items-center gap-3 border-b px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <p className="font-semibold">NS-Shield</p>
          <p className="text-xs text-muted-foreground">NyuwunSewu Shield</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navigation.map((item) => (
          <NavLink
            key={item.href}
            to={item.href}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "flex h-9 items-center gap-3 rounded-md px-3 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                isActive && "bg-primary/10 text-primary"
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.name}
          </NavLink>
        ))}
      </nav>
      <div className="border-t p-4">
        <div className="rounded-lg border bg-background p-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <p className="text-sm font-medium">MVP posture</p>
              <p className="mt-1 text-xs text-muted-foreground">Safe validation policy enabled</p>
            </div>
            <Badge variant="emerald">Guarded</Badge>
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
            <BarChart3 className="h-3.5 w-3.5" />
            Low-noise compliance evidence
          </div>
        </div>
      </div>
    </div>
  );
}
