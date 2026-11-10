
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string;
  change: string;
  description: string;
  icon: LucideIcon;
  color: string;
}

function StatCard({
  title,
  value,
  change,
  description,
  icon: Icon,
  color
}: StatCardProps) {

  return (

    <div className="stat-card">

      <div className="stat-card-header">

        <span className="stat-title">
          {title}
        </span>

        <div
          className="stat-icon"
          style={{ color: color }}
        >
          <Icon size={21} />
        </div>

      </div>

      <div className="stat-value">
        {value}
      </div>

      <div className="stat-footer">

        <span
          className="stat-change"
          style={{ color: color }}
        >
          {change}
        </span>

        <span className="stat-description">
          {description}
        </span>

      </div>

    </div>

  );

}

export default StatCard;
