import { useState, useEffect } from "react";

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

const DIRECTION_LABELS = {
  inbound: { arrow: "\u2193", text: "Inbound" },
  outbound: { arrow: "\u2191", text: "Outbound" },
  local: { arrow: "\u2194", text: "Local" },
};

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${h}:${m}:${s}.${ms}`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function groupHeaders(headers) {
  const groups = {};
  for (const h of headers) {
    const prefix = h.key.split(" ")[0];
    if (!groups[prefix]) groups[prefix] = [];
    groups[prefix].push(h);
  }
  return groups;
}

export default function PacketDetail({ packet, onClose }) {
  const [activeTab, setActiveTab] = useState("headers");

  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!packet) return null;

  const grouped = groupHeaders(packet.headers || []);
  const hasPayload = packet.payload_hex || packet.payload_text;
  const dirInfo = packet.direction && DIRECTION_LABELS[packet.direction];

  return (
    <div className="packet-detail-overlay" onClick={onClose}>
      <div
        className="packet-detail-panel"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="packet-detail-top">
          <div className="packet-detail-title-row">
            <span
              className="protocol-badge protocol-badge-lg"
              style={{
                background: PROTOCOL_COLORS[packet.protocol] || "#555",
              }}
            >
              {packet.protocol}
            </span>
            <span className="packet-detail-title">
              {packet.src_ip}
              <span className="detail-arrow">&rarr;</span>
              {packet.dst_ip}
            </span>
            <button className="packet-detail-close" onClick={onClose}>
              &times;
            </button>
          </div>

          <div className="packet-detail-meta">
            <div className="meta-item">
              <span className="meta-label">Time</span>
              <span className="meta-value mono">
                {formatTime(packet.timestamp)}
              </span>
            </div>
            <div className="meta-item">
              <span className="meta-label">Size</span>
              <span className="meta-value mono">
                {formatBytes(packet.size)}
              </span>
            </div>
            {packet.domain && (
              <div className="meta-item">
                <span className="meta-label">Domain</span>
                <span className="meta-value domain-val">
                  {packet.domain}
                </span>
              </div>
            )}
            {packet.src_port != null && (
              <div className="meta-item">
                <span className="meta-label">Ports</span>
                <span className="meta-value mono">
                  {packet.src_port} &rarr; {packet.dst_port}
                </span>
              </div>
            )}
            {dirInfo && (
              <div className="meta-item">
                <span className="meta-label">Direction</span>
                <span
                  className={`meta-value meta-direction ${packet.direction}`}
                >
                  {dirInfo.arrow} {dirInfo.text}
                </span>
              </div>
            )}
            {packet.ttl != null && (
              <div className="meta-item">
                <span className="meta-label">TTL</span>
                <span className="meta-value mono">{packet.ttl}</span>
              </div>
            )}
            {packet.tcp_flags && (
              <div className="meta-item">
                <span className="meta-label">TCP Flags</span>
                <span className="meta-value" style={{ color: "var(--amber)" }}>
                  {packet.tcp_flags}
                </span>
              </div>
            )}
            <div className="meta-item">
              <span className="meta-label">Info</span>
              <span className="meta-value">{packet.summary}</span>
            </div>
          </div>
        </div>

        <div className="packet-detail-tabs">
          <button
            className={`detail-tab ${activeTab === "headers" ? "active" : ""}`}
            onClick={() => setActiveTab("headers")}
          >
            Headers
            <span className="detail-tab-count">
              ({(packet.headers || []).length})
            </span>
          </button>
          <button
            className={`detail-tab ${activeTab === "payload" ? "active" : ""}`}
            onClick={() => setActiveTab("payload")}
          >
            Payload {hasPayload ? "" : "(empty)"}
          </button>
          <button
            className={`detail-tab ${activeTab === "hex" ? "active" : ""}`}
            onClick={() => setActiveTab("hex")}
          >
            Hex Dump
          </button>
        </div>

        <div className="packet-detail-body">
          {activeTab === "headers" && (
            <div className="headers-view">
              {(packet.headers || []).length === 0 ? (
                <div className="detail-empty">No headers available</div>
              ) : (
                Object.entries(grouped).map(([group, items]) => (
                  <div key={group} className="header-group">
                    <div className="header-group-title">{group}</div>
                    <table className="headers-table">
                      <tbody>
                        {items.map((h, i) => (
                          <tr key={i}>
                            <td className="header-key">{h.key}</td>
                            <td className="header-value mono">{h.value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === "payload" && (
            <div className="payload-view">
              {packet.payload_text ? (
                <pre className="payload-text mono">{packet.payload_text}</pre>
              ) : (
                <div className="detail-empty">No payload data</div>
              )}
            </div>
          )}

          {activeTab === "hex" && (
            <div className="hex-view">
              {packet.payload_hex ? (
                <pre className="hex-dump mono">{packet.payload_hex}</pre>
              ) : (
                <div className="detail-empty">No raw data</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
