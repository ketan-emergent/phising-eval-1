import { useState } from "react";
import { useAuth } from "@/App";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/lib/supabase";
import { Shield, ArrowRight, Mail, Lock, AlertCircle, Loader2 } from "lucide-react";

export default function LoginPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [signUpSuccess, setSignUpSuccess] = useState(false);

  if (user) {
    navigate("/", { replace: true });
    return null;
  }

  const validateEmail = (e) => {
    if (!e.endsWith("@emergent.sh")) {
      return "Only @emergent.sh email addresses are allowed";
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSignUpSuccess(false);

    const emailErr = validateEmail(email);
    if (emailErr) {
      setError(emailErr);
      return;
    }
    if (password.length < 6) {
      setError("Password must be at least 6 characters");
      return;
    }

    setSubmitting(true);
    try {
      if (isSignUp) {
        const { error: signUpError } = await supabase.auth.signUp({
          email,
          password,
        });
        if (signUpError) {
          const msg = signUpError.message || "";
          if (msg.includes("body stream") || msg.includes("JSON")) {
            setError("Sign up failed. Please try again.");
          } else {
            setError(msg);
          }
        } else {
          setSignUpSuccess(true);
        }
      } else {
        const { data, error: signInError } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        if (signInError) {
          const msg = signInError.message || "";
          if (msg.includes("body stream") || msg.includes("JSON")) {
            setError("Invalid email or password. Please try again.");
          } else {
            setError(msg);
          }
        } else if (data?.session) {
          localStorage.setItem("supabase_token", data.session.access_token);
          navigate("/", { replace: true });
        } else {
          setError("Sign in failed. Please check your credentials.");
        }
      }
    } catch (err) {
      const msg = err?.message || "";
      if (msg.includes("body stream") || msg.includes("JSON")) {
        setError("Invalid email or password. Please try again.");
      } else {
        setError(msg || "Authentication failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center" data-testid="login-page">
      <div className="w-full max-w-md px-6">
        <div className="flex flex-col items-center gap-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-mono font-bold tracking-wider uppercase text-foreground">
              Phishing Eval
            </h1>
          </div>
          <p className="text-sm text-muted-foreground text-center font-mono">
            Pipeline evaluation dashboard for phishing classification review
          </p>

          <form onSubmit={handleSubmit} className="w-full flex flex-col gap-4" data-testid="login-form">
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@emergent.sh"
                required
                data-testid="login-email-input"
                className="w-full bg-card border border-border text-foreground pl-10 pr-4 py-3 rounded-sm font-mono text-sm focus:outline-none focus:border-primary/50 transition-colors placeholder:text-muted-foreground/50"
              />
            </div>

            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                required
                data-testid="login-password-input"
                className="w-full bg-card border border-border text-foreground pl-10 pr-4 py-3 rounded-sm font-mono text-sm focus:outline-none focus:border-primary/50 transition-colors placeholder:text-muted-foreground/50"
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/20 px-3 py-2 rounded-sm" data-testid="login-error">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {signUpSuccess && (
              <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono bg-emerald-500/10 border border-emerald-500/20 px-3 py-2 rounded-sm" data-testid="signup-success">
                <span>Account created! Check your email to confirm, then sign in.</span>
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              data-testid="login-submit-btn"
              className="w-full flex items-center justify-center gap-3 bg-card border border-border hover:border-primary/50 text-foreground px-6 py-3 rounded-sm font-mono text-sm transition-all duration-150 hover:shadow-[0_0_12px_rgba(16,185,129,0.15)] group disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <span>{isSignUp ? "Create Account" : "Sign In"}</span>
                  <ArrowRight className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                </>
              )}
            </button>
          </form>

          <button
            onClick={() => { setIsSignUp(!isSignUp); setError(""); setSignUpSuccess(false); }}
            data-testid="toggle-auth-mode-btn"
            className="text-xs text-muted-foreground font-mono hover:text-primary transition-colors"
          >
            {isSignUp ? "Already have an account? Sign In" : "Need an account? Sign Up"}
          </button>

          <div className="text-xs text-muted-foreground/50 font-mono text-center mt-2">
            Authorized @emergent.sh personnel only
          </div>
        </div>
      </div>
    </div>
  );
}
