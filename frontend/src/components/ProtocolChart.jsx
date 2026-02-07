import { useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Label,
} from "recharts";

const COLORS = [
  "#6c9eff",
  "#ff6c6c",
  "#6cffb0",
  "#ffd76c",
  "#c46cff",
  "#6cfff5",
  "#ff9f6c",
  "#ff6cb0",
];

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { name, value, percent } = payload[0].payload;
  return (
    <div className="protocol-tooltip">
      <span className="protocol-tooltip-name">{name}</span>
      <span className="protocol-tooltip-val">
        {value.toLocaleString()} ({(percent * 100).toFixed(1)}%)
      </span>
    </div>
  );
}

function CenterLabel({ viewBox, total }) {
  if (!viewBox) return null;
  const { cx, cy } = viewBox;
  return (
    <g>
      <text
        x={cx}
        y={cy - 6}
        textAnchor="middle"
        fill="#e6edf3"
        fontSize={18}
        fontWeight={700}
      >
        {total >= 1000000
          ? `${(total / 1000000).toFixed(1)}M`
          : total >= 1000
          ? `${(total / 1000).toFixed(1)}K`
          : total}
      </text>
      <text
        x={cx}
        y={cy + 14}
        textAnchor="middle"
        fill="#8b949e"
        fontSize={10}
      >
        packets
      </text>
    </g>
  );
}

export default function ProtocolChart({ stats }) {
  if (!stats || !stats.protocol_counts) return null;

  const { data, total } = useMemo(() => {
    const entries = Object.entries(stats.protocol_counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
    const total = entries.reduce((sum, e) => sum + e.value, 0);
    const withPercent = entries.map((e) => ({
      ...e,
      percent: total > 0 ? e.value / total : 0,
    }));
    return { data: withPercent, total };
  }, [stats.protocol_counts]);

  if (data.length === 0) return null;

  return (
    <div className="chart-card protocol-chart-card">
      <h3>Protocols</h3>
      <div className="protocol-chart-layout">
        <div className="protocol-chart-pie">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={85}
                paddingAngle={2}
                isAnimationActive={false}
              >
                {data.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
                <Label content={<CenterLabel total={total} />} position="center" />
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="protocol-legend">
          {data.map((entry, i) => (
            <div key={entry.name} className="protocol-legend-item">
              <span
                className="protocol-legend-dot"
                style={{ background: COLORS[i % COLORS.length] }}
              />
              <span className="protocol-legend-name">{entry.name}</span>
              <span className="protocol-legend-count">
                {entry.value.toLocaleString()}
              </span>
              <span className="protocol-legend-pct">
                {(entry.percent * 100).toFixed(1)}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
