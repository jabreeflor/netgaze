import { useMemo } from "react";

export default function TrafficFlowChart({ packets, stats }) {
  const directionCounts = useMemo(() => {
    const counts = { inbound: 0, outbound: 0, local: 0 };
    if (!packets) return counts;
    for (const pkt of packets) {
      const dir = pkt.direction || "local";
      if (counts[dir] !== undefined) counts[dir]++;
    }
    return counts;
  }, [packets]);

  const total =
    directionCounts.inbound + directionCounts.outbound + directionCounts.local;

  const pct = (val) => (total > 0 ? ((val / total) * 100).toFixed(1) : "0.0");

  const connectionCount = stats?.connection_count || 0;

  return (
    <div className="chart-card traffic-flow-card">
      <h3>Traffic Flow</h3>
      <div className="traffic-flow-content">
        <div className="traffic-flow-bar-container">
          {total > 0 ? (
            <div className="traffic-flow-bar">
              {directionCounts.inbound > 0 && (
                <div
                  className="traffic-flow-segment traffic-flow-inbound"
                  style={{
                    width: `${pct(directionCounts.inbound)}%`,
                  }}
                />
              )}
              {directionCounts.outbound > 0 && (
                <div
                  className="traffic-flow-segment traffic-flow-outbound"
                  style={{
                    width: `${pct(directionCounts.outbound)}%`,
                  }}
                />
              )}
              {directionCounts.local > 0 && (
                <div
                  className="traffic-flow-segment traffic-flow-local"
                  style={{
                    width: `${pct(directionCounts.local)}%`,
                  }}
                />
              )}
            </div>
          ) : (
            <div className="traffic-flow-bar traffic-flow-bar-empty">
              <span>No traffic data</span>
            </div>
          )}
        </div>
        <div className="traffic-flow-stats">
          <div className="traffic-flow-stat">
            <span className="traffic-flow-dot traffic-flow-inbound-dot" />
            <span className="traffic-flow-stat-label">Inbound</span>
            <span className="traffic-flow-stat-value">
              {directionCounts.inbound.toLocaleString()}
            </span>
            <span className="traffic-flow-stat-pct">
              {pct(directionCounts.inbound)}%
            </span>
          </div>
          <div className="traffic-flow-stat">
            <span className="traffic-flow-dot traffic-flow-outbound-dot" />
            <span className="traffic-flow-stat-label">Outbound</span>
            <span className="traffic-flow-stat-value">
              {directionCounts.outbound.toLocaleString()}
            </span>
            <span className="traffic-flow-stat-pct">
              {pct(directionCounts.outbound)}%
            </span>
          </div>
          <div className="traffic-flow-stat">
            <span className="traffic-flow-dot traffic-flow-local-dot" />
            <span className="traffic-flow-stat-label">Local</span>
            <span className="traffic-flow-stat-value">
              {directionCounts.local.toLocaleString()}
            </span>
            <span className="traffic-flow-stat-pct">
              {pct(directionCounts.local)}%
            </span>
          </div>
          <div className="traffic-flow-stat traffic-flow-connections">
            <span className="traffic-flow-stat-label">Connections</span>
            <span className="traffic-flow-stat-value">
              {connectionCount.toLocaleString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
