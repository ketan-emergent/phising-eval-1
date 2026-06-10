import { useState, useEffect, useCallback, createContext, useContext } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import axios from "axios";
import { supabase } from "@/lib/supabase";
import LoginPage from "@/pages/LoginPage";
import Dashboard from "@/pages/Dashboard";
import AutomationDashboard from "@/pages/AutomationDashboard";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Attach token to every request as both header and query param
// Header works for direct calls, query param survives proxy 307 redirects that strip headers
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem("supabase_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
    // Also pass as query param for proxy redirect resilience
    const separator = config.url?.includes("?") ? "&" : "?";
    config.url = `${config.url}${separator}_token=${token}`;
  }
  return config;
});

const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

export { API, BACKEND_URL };

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const syncSession = useCallback((session) => {
    if (session?.access_token) {
      localStorage.setItem("supabase_token", session.access_token);
      // Set cookie on parent domain so it survives proxy redirects to internal subdomain
      const host = window.location.hostname;
      const domainParts = host.split(".");
      const cookieDomain = domainParts.length > 2 ? "." + domainParts.slice(1).join(".") : host;
      document.cookie = `sb_token=${session.access_token}; path=/; max-age=${60 * 60 * 24 * 7}; domain=${cookieDomain}; SameSite=None; Secure`;
      setUser({
        email: session.user?.email,
        name: session.user?.user_metadata?.name || session.user?.email?.split("@")[0],
        user_id: session.user?.id,
      });
    } else {
      localStorage.removeItem("supabase_token");
      const host = window.location.hostname;
      const domainParts = host.split(".");
      const cookieDomain = domainParts.length > 2 ? "." + domainParts.slice(1).join(".") : host;
      document.cookie = `sb_token=; path=/; max-age=0; domain=${cookieDomain}; SameSite=None; Secure`;
      setUser(null);
    }
  }, []);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      syncSession(session);
      setLoading(false);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      syncSession(session);
    });

    return () => subscription.unsubscribe();
  }, [syncSession]);

  const logout = async () => {
    await supabase.auth.signOut();
    localStorage.removeItem("supabase_token");
    const host = window.location.hostname;
    const domainParts = host.split(".");
    const cookieDomain = domainParts.length > 2 ? "." + domainParts.slice(1).join(".") : host;
    document.cookie = `sb_token=; path=/; max-age=0; domain=${cookieDomain}; SameSite=None; Secure`;
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, loading, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="flex flex-col items-center gap-4">
          <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <span className="text-sm text-muted-foreground font-mono">Loading...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

function AppRouter() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/automation"
        element={
          <ProtectedRoute>
            <AutomationDashboard />
          </ProtectedRoute>
        }
      />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="noise-overlay" />
        <AppRouter />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
