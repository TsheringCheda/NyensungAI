
import {
  Shield,
  LayoutDashboard,
  Activity,
  Bell,
  ClipboardList,
  FileText,
  Settings,
  ChevronLeft,
  type LucideIcon,
} from "lucide-react";

interface SidebarProps {
  activePage: string;
  onNavigate: (page: string) => void;
}

interface NavigationItem {
  name: string;
  icon: LucideIcon;
}

interface NavigationGroup {
  title: string;
  items: NavigationItem[];
}

const navigation: NavigationGroup[] = [
  {
    title: "OVERVIEW",
    items: [
      { name: "Dashboard", icon: LayoutDashboard },
      { name: "Threat Monitoring", icon: Activity },
    ],
  },
  {
    title: "SECURITY OPERATIONS",
    items: [
      { name: "Security Alerts", icon: Bell },
      { name: "Incidents", icon: ClipboardList },
      { name: "Reports", icon: FileText },
    ],
  },
  {
    title: "SYSTEM",
    items: [
      { name: "Settings", icon: Settings },
    ],
  },
];

function Sidebar({ activePage, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <Shield size={28} aria-hidden="true" />
        <h2>
          NYENSUNG<span>AI</span>
        </h2>
      </div>

      {/* Monitoring Status */}
      <div className="sidebar-status">
        <span className="status-dot" />
        DEFENSIVE MONITORING
      </div>

      {/* Navigation */}
      <nav
        className="sidebar-navigation"
        aria-label="Main navigation"
      >
        {navigation.map((group) => (
          <div className="nav-group" key={group.title}>
            <p className="nav-heading">{group.title}</p>

            {group.items.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.name;

              return (
                <button
                  key={item.name}
                  type="button"
                  className={`nav-item ${isActive ? "active" : ""}`}
                  onClick={() => onNavigate(item.name)}
                  aria-current={isActive ? "page" : undefined}
                >
                  <Icon size={19} aria-hidden="true" />
                  <span>{item.name}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Sidebar Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-footer-icon">
          <Shield size={19} aria-hidden="true" />
        </div>

        <div>
          <strong>NyensungAI</strong>
          <p>Defensive Security Platform</p>
        </div>

        <ChevronLeft size={17} aria-hidden="true" />
      </div>
    </aside>
  );
}

export default Sidebar;
