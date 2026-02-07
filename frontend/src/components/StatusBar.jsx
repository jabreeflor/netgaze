function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(startTime) {
  if (!startTime) return "-";
  const elapsed = Math.floor(Date.now() / 1000 - startTime);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export default function StatusBar({ connected, stats }) {
  return (
    <div className="status-bar">
      <div className="status-item">
        <span
          className={`status-dot ${connected ? "connected" : "disconnected"}`}
        />
        {connected ? "Connected" : "Disconnected"}
      </div>
      {stats && (
        <>
          <div className="status-item">
            <span className="status-label">Interface</span>
            {stats.interface || "-"}
          </div>
          <div className="status-item">
            <span className="status-label">Packets</span>
            {stats.total_packets.toLocaleString()}
          </div>
          <div className="status-item">
            <span className="status-label">Data</span>
            {formatBytes(stats.total_bytes)}
          </div>
          <div className="status-item">
            <span className="status-label">Rate</span>
            {stats.packets_per_sec.toFixed(0)} pkt/s
          </div>
          <div className="status-item">
            <span className="status-label">Capture</span>
            {stats.capture_active ? "Active" : "Stopped"}
            {stats.start_time && ` (${formatDuration(stats.start_time)})`}
          </div>
        </>
      )}
    </div>
  );
}
