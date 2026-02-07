import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

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

export default function ProtocolChart({ stats }) {
  if (!stats || !stats.protocol_counts) return null;

  const data = Object.entries(stats.protocol_counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8);

  if (data.length === 0) return null;

  return (
    <div className="chart-card">
      <h3>Protocols</h3>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={90}
            paddingAngle={2}
            isAnimationActive={false}
          >
            {data.map((_, i) => (
              <Cell key={i} fill={COLORS[i % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#1e1e2e", border: "1px solid #444" }}
          />
          <Legend
            wrapperStyle={{ fontSize: 12 }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
