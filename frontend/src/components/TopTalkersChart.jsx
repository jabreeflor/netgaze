import { useState, useMemo } from "react";
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

const BAR_COLOR = "#6c9eff";
const BAR_COLOR_ALT = "#c46cff";

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { ip, count } = payload[0].payload;
  return (
    <div className="talkers-tooltip">
      <span className="talkers-tooltip-ip">{ip}</span>
      <span className="talkers-tooltip-count">
        {count.toLocaleString()} packets
      </span>
    </div>
  );
}

export default function TopTalkersChart({ stats }) {
  const [mode, setMode] = useState("sources");

  const data = useMemo(() => {
    if (!stats) return [];
    const raw =
      mode === "sources" ? stats.top_talkers : stats.top_destinations;
    if (!raw) return [];
    return Object.entries(raw)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [stats, mode]);

  if (!stats || (!stats.top_talkers && !stats.top_destinations)) return null;

  const color = mode === "sources" ? BAR_COLOR : BAR_COLOR_ALT;

  return (
    <div className="chart-card top-talkers-card">
      <div className="top-talkers-header">
        <h3>Top {mode === "sources" ? "Sources" : "Destinations"}</h3>
        <div className="top-talkers-toggle">
          <button
            className={`toggle-btn ${mode === "sources" ? "active" : ""}`}
            onClick={() => setMode("sources")}
          >
            Sources
          </button>
          <button
            className={`toggle-btn ${
              mode === "destinations" ? "active" : ""
            }`}
            onClick={() => setMode("destinations")}
          >
            Destinations
          </button>
        </div>
      </div>
      {data.length === 0 ? (
        <div className="chart-empty">No data yet</div>
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
              dataKey="ip"
              width={120}
              stroke="#555"
              tick={{ fontSize: 10, fill: "#8b949e" }}
            />
            <Tooltip content={<CustomTooltip />} cursor={false} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} isAnimationActive={false}>
              {data.map((_, i) => (
                <Cell key={i} fill={color} fillOpacity={1 - i * 0.06} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
