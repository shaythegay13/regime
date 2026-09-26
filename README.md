# Sentinel

Sentinel is a simulated security-operations investigation system that uses persisted incident memory to adapt investigation ordering. It includes a Python investigation backend, MongoDB Atlas persistence, a read-only demo API, and a Next.js replay interface.

## What it demonstrates

- Deterministic security incident investigations with bounded tool calls.
- MongoDB-backed alerts, investigation trajectories, outcomes, incident memories, agent runs, and adaptation comparisons.
- Similar-incident retrieval that deduplicates by incident, applies a configurable similarity threshold, and weights tool ordering by similarity.
- A replayable frontend demo that presents the latest persisted memory-enabled investigation without triggering a new investigation on page load.

## Repository layout

| Path | Purpose |
| --- | --- |
| `sentinel/` | Python investigation engine, CLI, MongoDB persistence, and demo API |
| `sentinel/api/demo.py` | Vercel serverless adapter for `GET /api/demo` |
| `frontend/` | Next.js frontend that fetches and replays the persisted demo run |

## Requirements

- Python 3.11+
- Node.js 20+
- MongoDB Atlas connection string for persistence and the demo API

## Configuration

Create a root `.env.local` file (it is gitignored):

```dotenv
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/
MONGODB_DATABASE=sentinel
```

The agent CLI may also require its separately configured model credentials when running `--agent`. The persisted frontend demo does not make a new agent or model call.

## Run locally

### Backend

```powershell
cd sentinel
py -m pip install -e ".[dev]"
py -m sentinel.demo_server
```

The read-only API is available at `http://127.0.0.1:8000/api/demo` and returns the latest completed memory-enabled agent run from MongoDB.

### Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:3000`. The frontend requests the backend through `/api/investigate`; it uses `http://127.0.0.1:8000` by default. If the backend is unavailable, the UI retains its local fallback demo data.

## Run investigations

From `sentinel/`:

```powershell
# Deterministic local investigation
py -m sentinel.cli --incident CREDENTIAL_COMPROMISE

# Persist a deterministic investigation to MongoDB Atlas
py -m sentinel.cli --incident CREDENTIAL_COMPROMISE --persist

# Run an agent investigation with recalled memory
py -m sentinel.cli --incident CREDENTIAL_COMPROMISE_VARIANT --agent --memory

# Compare baseline and memory-guided investigation plans
py -m sentinel.cli --compare CREDENTIAL_COMPROMISE_VARIANT
```

## MongoDB data

The default database is `sentinel`. Sentinel stores data in these collections:

- `incidents`
- `investigation_steps`
- `incident_memories`
- `harness_versions`
- `agent_runs`
- `adaptation_runs`

Use Atlas **Browse Collections** to confirm persisted documents. The frontend demo selects the most recent memory-enabled document in `agent_runs`, its corresponding incident, adaptation run, and recalled incident memory.

## Tests

Run the backend suite from `sentinel/`:

```powershell
py -m pytest -q
```

MongoDB integration tests run only when `MONGODB_URI` is configured and otherwise skip cleanly.

Build the frontend from `frontend/`:

```powershell
npm run build
```

## Deployment

Deploy the backend as a Vercel project rooted at `sentinel/`. Its read-only endpoint is `GET /api/demo`; configure `MONGODB_URI` and `MONGODB_DATABASE=sentinel` in the backend project environment.

Deploy the frontend as a separate Vercel project rooted at `frontend/`, with:

```dotenv
SENTINEL_API_URL=https://<your-backend-domain>
```

`SENTINEL_API_URL` must be the backend base URL, not the full `/api/demo` URL. It is only read server-side by the Next.js route, so MongoDB credentials remain on the backend.
