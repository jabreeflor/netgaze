import { useState, useEffect, useRef, useMemo } from "react";
import {
  AreaChart,
  Area,
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

function formatPps(pps) {
  if (pps < 1000) return `${pps} pps`;
  if (pps < 1000000) return `${(pps / 1000).toFixed(1)}K pps`;
  return `${(pps / 1000000).toFixed(1)}M pps`;
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const bytesEntry = payload.find((p) => p.dataKey === "bytesPerSec");
  const ppsEntry = payload.find((p) => p.dataKey === "packetsPerSec");
  return (
    <div className="bandwidth-tooltip">
      <div className="bandwidth-tooltip-time">{formatTime(label)}</div>
      {bytesEntry && (
        <div className="bandwidth-tooltip-row">
          <span
            className="bandwidth-tooltip-dot"
            style={{ background: "#6c9eff" }}
          />
          <span>Throughput:</span>
          <span className="bandwidth-tooltip-val">
            {formatBytes(bytesEntry.value)}
          </span>
        </div>
      )}
      {ppsEntry && (
        <div className="bandwidth-tooltip-row">
          <span
            className="bandwidth-tooltip-dot"
            style={{ background: "#c46cff" }}
          />
          <span>Packets:</span>
          <span className="bandwidth-tooltip-val">
            {formatPps(ppsEntry.value)}
          </span>
        </div>
      )}
    </div>
  );
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

    // Use bandwidth_history if available, otherwise build from live stats
    if (stats.bandwidth_history && stats.bandwidth_history.length > 0) {
      setData(
        stats.bandwidth_history.map((h) => ({
          time: h.timestamp ? h.timestamp * 1000 : Date.now(),
          bytesPerSec: h.bytes_per_sec || 0,
          packetsPerSec: h.packets_per_sec || 0,
        }))
      );
    } else {
      setData((prev) => {
        const point = {
          time: Date.now(),
          bytesPerSec: stats.bytes_per_sec || 0,
          packetsPerSec: stats.packets_per_sec || 0,
        };
        const next = [...prev, point];
        return next.slice(-MAX_POINTS);
      });
    }
  }, [stats]);

  const summaryStats = useMemo(() => {
    if (data.length === 0)
      return { current: 0, avg: 0, peak: 0, currentPps: 0 };
    const bytes = data.map((d) => d.bytesPerSec);
    const current = bytes[bytes.length - 1] || 0;
    const avg = Math.round(bytes.reduce((a, b) => a + b, 0) / bytes.length);
    const peak = Math.max(...bytes);
    const currentPps = data[data.length - 1]?.packetsPerSec || 0;
    return { current, avg, peak, currentPps };
  }, [data]);

  return (
    <div className="chart-card bandwidth-chart-card">
      <h3>Bandwidth</h3>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="bwGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#6c9eff" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#6c9eff" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#c46cff" stopOpacity={0.15} />
              <stop offset="100%" stopColor="#c46cff" stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#222" />
          <XAxis
            dataKey="time"
            tickFormatter={formatTime}
            stroke="#555"
            tick={{ fontSize: 10 }}
          />
          <YAxis
            yAxisId="bytes"
            orientation="left"
            tickFormatter={formatBytes}
            stroke="#555"
            tick={{ fontSize: 10 }}
            width={75}
          />
          <YAxis
            yAxisId="pps"
            orientation="right"
            tickFormatter={formatPps}
            stroke="#555"
            tick={{ fontSize: 10 }}
            width={65}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            yAxisId="bytes"
            type="monotone"
            dataKey="bytesPerSec"
            stroke="#6c9eff"
            strokeWidth={2}
            fill="url(#bwGradient)"
            dot={false}
            name="Throughput"
            isAnimationActive={false}
          />
          <Area
            yAxisId="pps"
            type="monotone"
            dataKey="packetsPerSec"
            stroke="#c46cff"
            strokeWidth={1.5}
            fill="url(#ppsGradient)"
            dot={false}
            name="Packets/sec"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
      <div className="bandwidth-summary">
        <div className="bandwidth-stat">
          <span className="bandwidth-stat-label">Current</span>
          <span className="bandwidth-stat-value">
            {formatBytes(summaryStats.current)}
          </span>
        </div>
        <div className="bandwidth-stat">
          <span className="bandwidth-stat-label">Average</span>
          <span className="bandwidth-stat-value">
            {formatBytes(summaryStats.avg)}
          </span>
        </div>
        <div className="bandwidth-stat">
          <span className="bandwidth-stat-label">Peak</span>
          <span className="bandwidth-stat-value bandwidth-stat-peak">
            {formatBytes(summaryStats.peak)}
          </span>
        </div>
        <div className="bandwidth-stat">
          <span className="bandwidth-stat-label">Packets</span>
          <span className="bandwidth-stat-value">
            {formatPps(summaryStats.currentPps)}
          </span>
        </div>
      </div>
    </div>
  );
}
