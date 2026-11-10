
import { useEffect, useState } from "react";

import {
  Shield,
  Eye,
  EyeOff,
  LockKeyhole,
  Activity,
  ShieldCheck
} from "lucide-react";

import {
  loginUser,
  getCurrentUser,
  logoutUser,
  type User
} from "./services/api";

import Dashboard from "./pages/Dashboard";

import "./App.css";

function App() {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [authChecking, setAuthChecking] = useState(true);

  const [error, setError] = useState("");
  const [user, setUser] = useState<User | null>(null);

  const [token, setToken] = useState(
    sessionStorage.getItem("nyensung_token") || sessionStorage.getItem("sentinel_token") || ""
  );

  // Restore an existing authenticated session
  useEffect(() => {

    const restoreSession = async () => {

      if (!token) {
        setAuthChecking(false);
        return;
      }

      try {

        const currentUser = await getCurrentUser(token);

        setUser(currentUser);

      } catch {

        sessionStorage.removeItem("nyensung_token");
        sessionStorage.removeItem("sentinel_token");

        setToken("");
        setUser(null);

      } finally {

        setAuthChecking(false);

      }

    };

    restoreSession();

  }, []);

  // Handle login
  const handleLogin = async (
    e: React.FormEvent<HTMLFormElement>
  ) => {

    e.preventDefault();

    setLoading(true);
    setError("");

    try {

      const response = await loginUser(email, password);

      sessionStorage.setItem(
        "nyensung_token",
        response.access_token
      );

      setToken(response.access_token);
      setUser(response.user);

      setPassword("");

    } catch (err) {

      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to the server."
      );

    } finally {

      setLoading(false);

    }

  };

  // Handle logout
  const handleLogout = async () => {

    try {

      if (token) {
        await logoutUser(token);
      }

    } catch (err) {

      console.error("Logout API error:", err);

    } finally {

      sessionStorage.removeItem("nyensung_token");
      sessionStorage.removeItem("sentinel_token");

      setToken("");
      setUser(null);
      setEmail("");
      setPassword("");
      setError("");

    }

  };

  // Authentication loading screen
  if (authChecking) {

    return (

      <div className="app-container">

        <div className="security-icon">
          <ShieldCheck size={42} />
        </div>

        <h2>Verifying NyensungAI session...</h2>

      </div>

    );

  }

  // Display dashboard after successful authentication
  if (user) {

    return (

      <Dashboard
        user={user}
        token={token}
        onLogout={handleLogout}
      />

    );

  }

  // Display login page
  return (

    <div className="app-container">

      <nav className="navbar">

        <div className="brand">

          <Shield className="brand-icon" size={30} />

          <h2>
            NYENSUNG<span>AI</span>
          </h2>

        </div>

        <div className="system-status">

          <span className="status-dot"></span>

          SYSTEM READY

        </div>

      </nav>

      <main className="main-content">

        <section className="login-section">

          <div className="security-icon">
            <ShieldCheck size={42} />
          </div>

          <p className="eyebrow">
            SECURITY OPERATIONS CENTER
          </p>

          <h1>
            Welcome to <span>NyensungAI</span>
          </h1>

          <p className="description">
            Intelligent Cyber Threat Detection
            and Incident Response Platform.
          </p>

          <form onSubmit={handleLogin}>

            <label>Email Address</label>

            <div className="input-box">

              <LockKeyhole size={18} />

              <input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />

            </div>

            <label>Password</label>

            <div className="input-box">

              <LockKeyhole size={18} />

              <input
                type={showPassword ? "text" : "password"}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />

              <button
                type="button"
                className="eye-button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={
                  showPassword ? "Hide password" : "Show password"
                }
              >

                {showPassword
                  ? <EyeOff size={18} />
                  : <Eye size={18} />
                }

              </button>

            </div>

            {error && (

              <p className="login-error" role="alert">
                {error}
              </p>

            )}

            <button
              type="submit"
              className="login-button"
              disabled={loading}
            >

              {loading
                ? "Authenticating..."
                : "Secure Login →"}

            </button>

          </form>

          <div className="security-note">

            <ShieldCheck size={16} />

            Protected Security Access

          </div>

        </section>

        <section className="feature-section">

          <div className="feature">

            <Activity size={24} />

            <h3>Real-Time Monitoring</h3>

            <p>
              Monitor security events and
              suspicious activities.
            </p>

          </div>

          <div className="feature">

            <ShieldCheck size={24} />

            <h3>AI Threat Detection</h3>

            <p>
              Identify unusual patterns using
              intelligent detection.
            </p>

          </div>

          <div className="feature">

            <LockKeyhole size={24} />

            <h3>Incident Response</h3>

            <p>
              Investigate alerts and manage
              security incidents.
            </p>

          </div>

        </section>

      </main>

      <footer>

        NYENSUNGAI © 2026

        <span> DEFENSIVE CYBERSECURITY PLATFORM</span>

      </footer>

    </div>

  );

}

export default App;
