
import { LogOut } from "lucide-react";
import type { User } from "../services/api";

interface TopbarProps {
  activePage: string;
  user: User;
  onLogout: () => void;
}

export default function Topbar({
  activePage,
  user,
  onLogout,
}: TopbarProps) {
  return (
    <header className="topbar">
      <div className="topbar-heading">
        <h2>{activePage}</h2>
        <p>
          Security Operations Center <span>/</span> {activePage}
        </p>
      </div>

      <div className="topbar-actions">
        <div className="topbar-environment">
          <span className="status-dot" />
          Local lab environment
        </div>

        <div className="profile-section">
          <div className="profile-avatar">
            {user.username.charAt(0).toUpperCase()}
          </div>

          <div className="profile-details">
            <strong>{user.username}</strong>
            <span>{user.role}</span>
          </div>

          <button
            type="button"
            className="topbar-logout"
            onClick={onLogout}
            title="Logout"
            aria-label="Logout"
          >
            <LogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
}
