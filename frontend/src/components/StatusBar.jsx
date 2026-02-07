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
  const isCapturing = stats?.capture_active;

  return (
    <div className="status-bar">
      <div className="status-segment status-segment-primary">
        <span
          className={`status-dot ${connected ? "connected" : "disconnected"}`}
        />
        <span
          className="status-connection-label"
          style={{ color: connected ? "var(--green)" : "var(--red)" }}
        >
          {connected ? "Online" : "Offline"}
        </span>
      </div>

      {isCapturing && (
        <div className="status-segment">
          <span className="status-dot capturing" />
          <div className="status-metric">
            <span className="status-label">Capture</span>
            <span className="status-value accent">Active</span>
          </div>
        </div>
      )}

      {stats && (
        <>
          <div className="status-segment">
            <div className="status-metric">
              <span className="status-label">Interface</span>
              <span className="status-value">{stats.interface || "-"}</span>
            </div>
          </div>

          <div className="status-segment">
            <div className="status-metric">
              <span className="status-label">Packets</span>
              <span className="status-value">
                {stats.total_packets.toLocaleString()}
              </span>
            </div>
          </div>

          <div className="status-segment">
            <div className="status-metric">
              <span className="status-label">Data</span>
              <span className="status-value">
                {formatBytes(stats.total_bytes)}
              </span>
            </div>
          </div>

          <div className="status-segment">
            <div className="status-metric">
              <span className="status-label">Rate</span>
              <span className="status-value accent">
                {stats.packets_per_sec.toFixed(0)} pkt/s
              </span>
            </div>
          </div>

          {stats.start_time && (
            <div className="status-segment">
              <div className="status-metric">
                <span className="status-label">Duration</span>
                <span className="status-value">
                  {formatDuration(stats.start_time)}
                </span>
              </div>
            </div>
          )}
        </>
      )}

      {!stats && !isCapturing && (
        <div className="status-segment">
          <div className="status-metric">
            <span className="status-label">Status</span>
            <span className="status-value" style={{ color: "var(--text-muted)" }}>
              Idle
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
