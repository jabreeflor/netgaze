import { useState, useEffect, useRef } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const MAX_POINTS = 60;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB/s`;
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

export default function BandwidthChart({ stats }) {
  const [data, setData] = useState([]);
  const prevStats = useRef(null);

  useEffect(() => {
    if (!stats) return;
    if (
      prevStats.current &&
      prevStats.current.total_packets === stats.total_packets
    )
      return;
    prevStats.current = stats;

    setData((prev) => {
      const point = {
        time: Date.now(),
        bytesPerSec: stats.bytes_per_sec,
        packetsPerSec: stats.packets_per_sec,
      };
      const next = [...prev, point];
      return next.slice(-MAX_POINTS);
    });
  }, [stats]);

  return (
    <div className="chart-card">
      <h3>Bandwidth</h3>
      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#333" />
          <XAxis
            dataKey="time"
            tickFormatter={formatTime}
            stroke="#888"
            tick={{ fontSize: 11 }}
          />
          <YAxis
            tickFormatter={formatBytes}
            stroke="#888"
            tick={{ fontSize: 11 }}
            width={80}
          />
          <Tooltip
            formatter={(value) => formatBytes(value)}
            labelFormatter={formatTime}
            contentStyle={{ background: "#1e1e2e", border: "1px solid #444" }}
          />
          <Line
            type="monotone"
            dataKey="bytesPerSec"
            stroke="#6c9eff"
            strokeWidth={2}
            dot={false}
            name="Throughput"
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
