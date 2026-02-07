import { useState, useEffect, useCallback } from "react";
import useWebSocket from "../hooks/useWebSocket";
import BandwidthChart from "./BandwidthChart";
import ProtocolChart from "./ProtocolChart";
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

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1 className="app-title">NetGaze</h1>
          <p className="app-subtitle">Network Traffic Viewer</p>
        </div>
        <div className="controls">
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
          {error}
          <button className="error-dismiss" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      <StatusBar connected={connected} stats={stats} />

      {!capturing && packets.length === 0 ? (
        <div className="empty-state">
          <p className="empty-title">No traffic captured</p>
          <p className="empty-desc">
            Select a network interface and click Start Capture to begin
            monitoring.
          </p>
        </div>
      ) : (
        <>
          <div className="charts-row">
            <BandwidthChart stats={stats} />
            <ProtocolChart stats={stats} />
          </div>
          <PacketTable packets={packets} />
        </>
      )}
    </div>
  );
}
