# Administrator guide

- Start the backend with `uvicorn app.main:app --reload --port 8000` from the backend directory.
- Review device status, alerts, and transfers at `/devices`, `/alerts`, and `/transfers`.
- Use `/policies` to allow or block known devices.
- Use `/sync/status` to monitor queue backlog.
