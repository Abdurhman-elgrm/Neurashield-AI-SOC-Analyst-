# NeuraShield — AI SOC Analyst Platform

NeuraShield is a full Security Operations Center (SOC) platform that pairs SIEM-style alert ingestion with an AI agent that triages, analyzes, and helps respond to security events — all wrapped in a live operator dashboard.

## Features

- **AI Analysis Agent** — automated triage and contextual analysis of incoming security alerts
- **Real-time Dashboard** — interface for analysts to monitor, investigate, and act on alerts
- **Alert Pipeline** — backend services for ingesting, processing, and storing security events
- **Background Workers** — asynchronous job processing for analysis tasks
- **Dockerized Stack** — one-command local environment with Postgres and Redis included

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Frontend | React + Vite |
| Database | PostgreSQL |
| Cache / Queue | Redis |
| Orchestration | Docker Compose |

## Project Structure

```
.
├── agent/            # AI analysis agent logic
├── backend/           # Backend application and background workers
├── frontend/           # React dashboard (Vite)
├── installer/          # Setup / installation scripts
├── load-tests/          # Load and performance testing
├── docs/              # Project documentation
└── docker-compose.yml      # Full local dev stack
```

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Node.js (for local frontend development outside Docker, optional)
- Python 3.11+ (for local backend development outside Docker, optional)

### Setup

1. Clone the repository
   ```bash
   git clone https://github.com/Abdurhman-elgrm/Neurashield-AI-SOC-Analyst-.git
   cd Neurashield-AI-SOC-Analyst-
   ```

2. Set up your local environment configuration (see `.env.example` for required variables).

3. Start the full stack
   ```bash
   docker-compose up --build
   ```

4. Access the dashboard once the stack is running.

## Architecture

The stack runs five core services:

- **db** — PostgreSQL for persistent storage
- **redis** — caching and queue backend
- **backend** — core application logic and request handling
- **worker** — background worker for async analysis jobs
- **frontend** — React dashboard served via Vite

All services are networked together through Docker Compose with health checks gating startup order.

## Contributing

Issues and pull requests are welcome. Please open an issue first to discuss any significant changes.

## License

This project does not currently specify a license. Contact the repository owner for usage permissions.
