import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const BAR_COLOR = "#6cffb0";

function truncateDomain(domain, max = 28) {
  if (domain.length <= max) return domain;
  return domain.slice(0, max - 1) + "\u2026";
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { domain, count } = payload[0].payload;
  return (
    <div className="domains-tooltip">
      <span className="domains-tooltip-domain">{domain}</span>
      <span className="domains-tooltip-count">
        {count.toLocaleString()} requests
      </span>
    </div>
  );
}

export default function TopDomainsChart({ stats }) {
  const data = useMemo(() => {
    if (!stats || !stats.top_domains) return [];
    return Object.entries(stats.top_domains)
      .map(([domain, count]) => ({
        domain,
        displayDomain: truncateDomain(domain),
        count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [stats]);

  if (!stats || !stats.top_domains) return null;

  return (
    <div className="chart-card domains-chart-card">
      <h3>Top Domains</h3>
      {data.length === 0 ? (
        <div className="chart-empty">No DNS data yet</div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} layout="vertical" barSize={14}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#222"
              horizontal={false}
            />
            <XAxis
              type="number"
              stroke="#555"
              tick={{ fontSize: 10 }}
              tickFormatter={(v) =>
                v >= 1000 ? `${(v / 1000).toFixed(0)}K` : v
              }
            />
            <YAxis
              type="category"
              dataKey="displayDomain"
              width={160}
              stroke="#555"
              tick={{ fontSize: 10, fill: "#8b949e" }}
            />
            <Tooltip content={<CustomTooltip />} cursor={false} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} isAnimationActive={false}>
              {data.map((_, i) => (
                <Cell key={i} fill={BAR_COLOR} fillOpacity={1 - i * 0.06} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
