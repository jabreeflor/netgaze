import { useRef, useEffect, useState } from "react";

const PROTOCOL_COLORS = {
  TCP: "#6c9eff",
  UDP: "#6cffb0",
  HTTPS: "#ffd76c",
  HTTP: "#ff9f6c",
  DNS: "#c46cff",
  ICMP: "#ff6c6c",
  ARP: "#6cfff5",
  SSH: "#ff6cb0",
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
        <h3>Packets</h3>
        <span className="packet-count">{packets.length} shown</span>
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
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Domain</th>
              <th>Port</th>
              <th>Size</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, i) => (
              <tr key={`${pkt.timestamp}-${i}`}>
                <td className="mono">{formatTime(pkt.timestamp)}</td>
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
                <td className="mono">
                  {formatPort(pkt.src_port)} &rarr; {formatPort(pkt.dst_port)}
                </td>
                <td className="mono">{pkt.size}</td>
                <td className="info-cell">{pkt.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
