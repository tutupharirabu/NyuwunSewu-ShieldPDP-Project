import { Navigate, Outlet, useLocation } from "react-router-dom";

import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/context/auth-context";

export function ProtectedRoute() {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="w-full max-w-sm space-y-3">
          <Skeleton className="h-9 w-40" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-9 w-64" />
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}

