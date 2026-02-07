# NetGaze

A user-friendly network traffic viewer — a Wireshark alternative focused on simplicity and visual clarity.

## Features

- **Live Traffic Dashboard**: Real-time bandwidth monitoring
- **Protocol Breakdown**: Visual pie chart of network protocols
- **Packet Table**: Scrolling list of captured packets
- **Interface Selector**: Choose which network interface to monitor

## Architecture

```
Browser (React) <--WebSocket--> FastAPI Server <--Scapy--> Network Interface
```

## Quick Start

### Backend

```bash
cd backend
pip install -r requirements.txt
sudo python3 main.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

### Tests

```bash
pytest backend/tests/
```

## Tech Stack

- **Backend**: Python 3.9+, FastAPI, Scapy, WebSockets
- **Frontend**: React (Vite), Recharts

## Note

Packet capture requires `sudo` privileges. Run the backend with elevated permissions.
