import { useState, useEffect, useCallback } from "react";
import useWebSocket from "../hooks/useWebSocket";
import BandwidthChart from "./BandwidthChart";
import ProtocolChart from "./ProtocolChart";
import TopTalkersChart from "./TopTalkersChart";
import TopDomainsChart from "./TopDomainsChart";
import TrafficFlowChart from "./TrafficFlowChart";
import PacketTable from "./PacketTable";
import StatusBar from "./StatusBar";

const WS_URL = `ws://${window.location.host}/ws`;
const API_BASE = "";

export default function Dashboard() {
  const { connected, packets, stats, clearPackets } = useWebSocket(WS_URL);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("en0");
  const [capturing, setCapturing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/interfaces`)
      .then((r) => r.json())
      .then((data) => {
        setInterfaces(data.interfaces || []);
        if (data.interfaces?.length > 0 && !data.interfaces.includes("en0")) {
          setSelectedInterface(data.interfaces[0]);
        }
      })
      .catch(() => setError("Failed to load interfaces"));
  }, []);

  useEffect(() => {
    if (stats) {
      setCapturing(stats.capture_active);
    }
  }, [stats]);

  const startCapture = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `${API_BASE}/api/capture/start?interface=${encodeURIComponent(selectedInterface)}`,
        { method: "POST" }
      );
      if (!res.ok) throw new Error("Failed to start capture");
      setCapturing(true);
      clearPackets();
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedInterface, clearPackets]);

  const stopCapture = useCallback(async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE}/api/capture/stop`, { method: "POST" });
      setCapturing(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const exportCapture = useCallback(async (format) => {
    setExporting(true);
    try {
      const res = await fetch(
        `${API_BASE}/api/export?format=${encodeURIComponent(format)}`
      );
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `netgaze_capture.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message);
    } finally {
      setExporting(false);
    }
  }, []);

  const hasData = packets.length > 0 || (stats && stats.total_packets > 0);

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-title-group">
          <div className="app-logo">
            <div className="app-logo-ring" />
          </div>
          <div>
            <h1 className="app-title">
              <span className="accent-char">N</span>et
              <span className="accent-char">G</span>aze
            </h1>
            <p className="app-subtitle">Network Traffic Viewer</p>
          </div>
        </div>
        <div className="controls">
          {hasData && (
            <>
              <div className="export-group">
                <button
                  className="btn btn-export"
                  onClick={() => exportCapture("json")}
                  disabled={exporting}
                  title="Export as JSON"
                >
                  {exporting ? "..." : "JSON"}
                </button>
                <button
                  className="btn btn-export"
                  onClick={() => exportCapture("csv")}
                  disabled={exporting}
                  title="Export as CSV"
                >
                  {exporting ? "..." : "CSV"}
                </button>
              </div>
              <div className="controls-divider" />
            </>
          )}
          <select
            className="interface-select"
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={capturing || loading}
          >
            {interfaces.map((iface) => (
              <option key={iface} value={iface}>
                {iface}
              </option>
            ))}
          </select>
          {!capturing ? (
            <button
              className="btn btn-primary"
              onClick={startCapture}
              disabled={loading || !connected}
            >
              {loading ? "Starting..." : "Start Capture"}
            </button>
          ) : (
            <button
              className="btn btn-danger"
              onClick={stopCapture}
              disabled={loading}
            >
              {loading ? "Stopping..." : "Stop Capture"}
            </button>
          )}
        </div>
      </header>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button className="error-dismiss" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      <StatusBar connected={connected} stats={stats} />

      {!capturing && packets.length === 0 ? (
        <div className="empty-state">
          <div className="empty-radar">
            <div className="empty-radar-crosshair-h" />
            <div className="empty-radar-crosshair-v" />
            <div className="empty-radar-sweep" />
            <div className="empty-radar-center" />
          </div>
          <p className="empty-title">Awaiting Signal</p>
          <p className="empty-desc">
            Select a network interface and start capture to begin monitoring
            traffic in real time.
          </p>
          <div className="empty-hint">
            <span className="empty-hint-key">Step 1</span>
            Choose interface
            <span className="empty-hint-key">Step 2</span>
            Start capture
          </div>
        </div>
      ) : (
        <>
          <div className="charts-grid">
            <BandwidthChart stats={stats} />
            <ProtocolChart stats={stats} />
            <TopTalkersChart stats={stats} />
            <TopDomainsChart stats={stats} />
            <TrafficFlowChart packets={packets} stats={stats} />
          </div>
          <PacketTable packets={packets} />
        </>
      )}
    </div>
  );
}
