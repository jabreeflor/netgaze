import useWebSocket from "../hooks/useWebSocket";

const WS_URL = `ws://${window.location.host}/ws`;

export default function Dashboard() {
  const { connected, packets, stats } = useWebSocket(WS_URL);

  return (
    <div>
      <h1>NetGaze</h1>
      <p>Status: {connected ? "Connected" : "Disconnected"}</p>
      <p>Packets: {packets.length}</p>
      {stats && <p>Total: {stats.total_packets}</p>}
    </div>
  );
}
