# Sentinel

Sentinel is a defensive, simulated cybersecurity investigation harness. It runs
deterministic investigation plans and can optionally persist complete
investigations to MongoDB Atlas.

## Scope

Sentinel stores alerts, tool calls, observations, evidence, outcomes, and
structured incident memories. It does not include vector search, embeddings,
LLMs, Strands, a harness optimizer, or a frontend.

## Install

```bash
cd sentinel
pip install -e ".[dev]"
```

## Configure MongoDB Atlas

```bash
cp .env.example .env.local
```

Set the following values in `.env.local`:

```dotenv
MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/
MONGODB_DATABASE=sentinel
```

MongoDB is optional for normal local development and unit tests.

## Run investigations

Run without persistence:

```bash
python -m sentinel.cli --incident CREDENTIAL_COMPROMISE
```

Run and persist to Atlas:

```bash
python -m sentinel.cli --incident CREDENTIAL_COMPROMISE --persist
```

Run every scenario:

```bash
python -m sentinel.cli --incident all --persist
```

Demonstrate learning after `incident_memory_vector` reports `READY` in Atlas:

```bash
python -m sentinel.cli --incident CREDENTIAL_COMPROMISE --persist
python -m sentinel.cli --incident CREDENTIAL_COMPROMISE_VARIANT --persist --memory
python -m sentinel.cli --compare CREDENTIAL_COMPROMISE_VARIANT
```

List stored incident memories:

```bash
python -m sentinel.cli --list-memories --limit 20
```

If Atlas is unavailable or `MONGODB_URI` is not configured, `--persist` reports
the problem and the local investigation still completes.

## Persistence

`sentinel.memory_store.PersistenceStore` keeps application models separate
from MongoDB-specific serialization and exposes:

- `health_check()`
- `save_security_alert()`
- `save_investigation_step()`
- `save_incident_outcome()`
- `save_incident_memory()`
- `get_incident()`
- `get_investigation_trajectory()`
- `list_incident_memories()`
- `search_similar_memories()`

Each persisted investigation writes:

- The initial alert and final outcome to `incidents`.
- One action, observation, and extracted evidence document per tool call to
  `investigation_steps`.
- A structured `IncidentMemory` to `incident_memories`, including final
  classification, ground truth, critical evidence, tool counts, and useful or
  unnecessary tools where available.
- Run metadata to `harness_versions`.

## MongoDB collections

The default database is `sentinel` (configurable with `MONGODB_DATABASE`).

| Collection | Contents |
| --- | --- |
| `incidents` | Initial `SecurityAlert` and nested final `IncidentOutcome` |
| `investigation_steps` | One document per tool call with observation and evidence |
| `incident_memories` | Structured `IncidentMemory` record |
| `harness_versions` | Append-only persistence metadata |

## Semantic memory setup

Create this Atlas Vector Search index in the `sentinel.incident_memories`
collection. Name it `incident_memory_vector`:

```json
{
  "fields": [
    {
      "type": "autoEmbed",
      "modality": "text",
      "path": "narrative",
      "model": "voyage-4"
    }
  ]
}
```

In Atlas, open **Search & Vector Search** for `incident_memories`, select
**Create Search Index**, choose the JSON editor, paste the definition, set the
index name, and create it. Then run a prior credential-compromise incident with
`--persist`, followed by the variant with `--persist --memory` or `--compare`.

The application handles an absent or unavailable index by retaining the static
plan and reporting that no semantic memories were available.

## Tests

Run the complete suite:

```bash
pytest -q
```

MongoDB integration tests are in `tests/test_mongo_integration.py`. They skip
cleanly when `MONGODB_URI` is absent. When configured, they use and clean up the
isolated `sentinel_test` database.

## Verify in Atlas

After a persisted run, open Atlas **Browse Collections**, choose the `sentinel`
database (or your `MONGODB_DATABASE` value), and inspect:

- `incidents`: locate `alert_id: "INC-2026-001"`; its `outcome` field contains
  classification, ground truth, critical evidence, and total tool calls.
- `investigation_steps`: filter by `alert_id: "INC-2026-001"`; the default
  credential compromise run creates five ordered documents.
- `incident_memories`: locate the CLI-reported `memory_id`.
- `harness_versions`: filter by `alert_id: "INC-2026-001"` to see run metadata.
