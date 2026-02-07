import { useEffect, useRef, useState, useCallback } from "react";

const RECONNECT_DELAY = 2000;
const MAX_RECONNECT_DELAY = 30000;

export default function useWebSocket(url) {
  const [connected, setConnected] = useState(false);
  const [packets, setPackets] = useState([]);
  const [stats, setStats] = useState(null);
  const wsRef = useRef(null);
  const reconnectDelay = useRef(RECONNECT_DELAY);
  const reconnectTimer = useRef(null);
  const maxPackets = 500;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      reconnectDelay.current = RECONNECT_DELAY;
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.packets) {
        setPackets((prev) => {
          const combined = [...data.packets, ...prev];
          return combined.slice(0, maxPackets);
        });
      }
      if (data.stats) {
        setStats(data.stats);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      reconnectTimer.current = setTimeout(() => {
        reconnectDelay.current = Math.min(
          reconnectDelay.current * 1.5,
          MAX_RECONNECT_DELAY
        );
        connect();
      }, reconnectDelay.current);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clearPackets = useCallback(() => setPackets([]), []);

  return { connected, packets, stats, clearPackets };
}
