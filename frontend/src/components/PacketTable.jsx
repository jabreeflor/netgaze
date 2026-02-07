import { useRef, useEffect, useState } from "react";
import PacketDetail from "./PacketDetail";

const PROTOCOL_COLORS = {
  TCP: "#4facfe",
  UDP: "#43e97b",
  HTTPS: "#f9d423",
  HTTP: "#fa709a",
  DNS: "#a18cd1",
  ICMP: "#ff6b6b",
  ARP: "#38f9d7",
  SSH: "#f093fb",
};

const DIRECTION_CONFIG = {
  inbound: { arrow: "\u2193", label: "IN" },
  outbound: { arrow: "\u2191", label: "OUT" },
  local: { arrow: "\u2194", label: "LCL" },
};

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${h}:${m}:${s}.${ms}`;
}

function formatPort(port) {
  return port != null ? port : "-";
}

export default function PacketTable({ packets }) {
  const containerRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState(null);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [packets, autoScroll]);

  const handleScroll = () => {
    if (containerRef.current) {
      setAutoScroll(containerRef.current.scrollTop < 10);
    }
  };

  return (
    <div className="packet-table-card">
      <div className="packet-table-header">
        <div className="packet-table-title-group">
          <h3>Packet Stream</h3>
          <span className="packet-count">
            <strong>{packets.length}</strong> captured
          </span>
        </div>
        <div className="packet-table-controls">
          <button
            className={`auto-scroll-toggle ${autoScroll ? "active" : ""}`}
            onClick={() => setAutoScroll(!autoScroll)}
            title={autoScroll ? "Auto-scroll enabled" : "Auto-scroll disabled"}
          >
            <span className="auto-scroll-indicator" />
            Auto
          </button>
        </div>
      </div>
      <div
        className="packet-table-container"
        ref={containerRef}
        onScroll={handleScroll}
      >
        <table className="packet-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Dir</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>Domain</th>
              <th>Port</th>
              <th>Size</th>
              <th>Flags</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, i) => {
              const dirConf =
                pkt.direction && DIRECTION_CONFIG[pkt.direction];

              return (
                <tr
                  key={`${pkt.timestamp}-${i}`}
                  className={`packet-row ${selectedPacket === pkt ? "selected" : ""}`}
                  onClick={() => setSelectedPacket(pkt)}
                >
                  <td className="mono">{formatTime(pkt.timestamp)}</td>
                  <td>
                    {dirConf ? (
                      <span className={`direction-badge ${pkt.direction}`}>
                        <span className="direction-arrow">
                          {dirConf.arrow}
                        </span>
                        {dirConf.label}
                      </span>
                    ) : (
                      <span className="direction-badge">-</span>
                    )}
                  </td>
                  <td className="mono">{pkt.src_ip}</td>
                  <td className="mono">{pkt.dst_ip}</td>
                  <td>
                    <span
                      className="protocol-badge"
                      style={{
                        background:
                          PROTOCOL_COLORS[pkt.protocol] || "#555",
                      }}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="domain-cell" title={pkt.domain || ""}>
                    {pkt.domain || "-"}
                  </td>
                  <td className="port-cell mono">
                    {formatPort(pkt.src_port)}
                    <span className="port-arrow">&rarr;</span>
                    {formatPort(pkt.dst_port)}
                  </td>
                  <td className="size-cell mono">{pkt.size}</td>
                  <td className="tcp-flags-cell">
                    {pkt.tcp_flags || "-"}
                  </td>
                  <td className="info-cell">{pkt.summary}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {selectedPacket && (
        <PacketDetail
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  );
}
