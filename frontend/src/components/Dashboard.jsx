import useWebSocket from "../hooks/useWebSocket";
import BandwidthChart from "./BandwidthChart";
import ProtocolChart from "./ProtocolChart";
import PacketTable from "./PacketTable";
import StatusBar from "./StatusBar";

const WS_URL = `ws://${window.location.host}/ws`;

export default function Dashboard() {
  const { connected, packets, stats, clearPackets } = useWebSocket(WS_URL);

  return (
    <div className="app">
      <header className="app-header">
        <h1 className="app-title">NetGaze</h1>
        <p className="app-subtitle">Network Traffic Viewer</p>
      </header>

      <StatusBar connected={connected} stats={stats} />

      <div className="charts-row">
        <BandwidthChart stats={stats} />
        <ProtocolChart stats={stats} />
      </div>

      <PacketTable packets={packets} />
    </div>
  );
}
