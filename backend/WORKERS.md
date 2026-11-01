# AegisMesh 2.0 — Background Worker Infrastructure

This document describes the asynchronous task architecture powered by **Celery** and **Redis** for AegisMesh 2.0.

---

## Architecture Overview

```
+--------------------+        Enqueues task        +-------------------------+
|   FastAPI API      | --------------------------> |    Redis Broker (db 0)  |
|  (POST /jobs/...)  |                             | (redis://localhost:6379)|
+--------------------+                             +-------------------------+
          |                                                     |
          | Polls status                                        | Consumes tasks
          v                                                     v
+-------------------------+       Saves results    +-------------------------+
| Redis Result Backend    | <--------------------- |      Celery Worker      |
|         (db 1)          |                        |  (app.workers.celery_app)
+-------------------------+                        +-------------------------+
```

1. **Redis as Message Broker (`redis://localhost:6379/0`)**:
   FastAPI pushes serialized JSON job payloads into Redis lists. Redis acts as a fast, in-memory queue coordinating pending task requests.

2. **Celery Worker Execution**:
   Independent worker processes poll the Redis broker, deserialize JSON arguments, execute tasks, and record lifecycle states (`STARTED`, `SUCCESS`, `FAILURE`).

3. **Redis Result Backend (`redis://localhost:6379/1`)**:
   Upon task completion, task metadata, status, and JSON results are stored in Redis database 1 with a configurable TTL (default: 3600 seconds / 1 hour).

4. **FastAPI Job Submission & Monitoring**:
   FastAPI dispatches tasks asynchronously using `.delay()` and returns an immediate HTTP 202 Accepted with a unique `task_id`. Clients can poll `GET /api/v1/jobs/{task_id}` non-blockingly without tying up HTTP server threads.

---

## Starting the Celery Worker on Windows

### Important Windows Configuration Note

> **Note**: On Linux, Celery defaults to the `prefork` execution pool. However, Windows does not support POSIX `fork()`, which causes the prefork pool to hang, crash, or fail to spawn child worker processes on Windows.
>
> On Windows development environments, you **must** use Celery's `solo` worker pool:
> ```powershell
> --pool=solo
> ```

### Worker Startup Command

To start the Celery worker process:

```powershell
# Navigate to the backend directory
cd backend

# Activate your virtual environment
.\.venv\Scripts\activate

# Start the worker with the solo execution pool
celery -A app.workers.celery_app:celery_app worker --loglevel=info --pool=solo
```

Expected startup output:
```text
 -------------- celery@YOUR-MACHINE v5.6.3 (herald)
--- ***** ----- 
-- ******* ---- Windows-...
- *** --- * --- 
- ** ---------- [config]
- ** ---------- .> app:         aegismesh:0x...
- ** ---------- .> transport:   redis://localhost:6379/0
- ** ---------- .> results:     redis://localhost:6379/1
- *** --- * --- .> concurrency: 2 (solo)
-- ******* ---- .> task events: OFF (enable -E to monitor tasks in this worker)
--- ***** ----- 
 -------------- [queues]
                .> celery           exchange=celery(direct) key=celery

[tasks]
  . app.workers.tasks.health_check_task

[INFO/MainProcess] Connected to redis://localhost:6379/0
[INFO/MainProcess] celery@YOUR-MACHINE ready.
```

---

## Testing Background Jobs via Swagger UI

1. **Ensure Prerequisites Are Running**:
   - Docker containers: PostgreSQL, Redis (`docker compose ps`)
   - Celery worker: Running in a separate terminal (`celery -A app.workers.celery_app:celery_app worker --loglevel=info --pool=solo`)
   - FastAPI backend: Running on port 8000 (`uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`)

2. **Open Interactive Documentation**:
   Navigate to [http://localhost:8000/docs](http://localhost:8000/docs) in your browser.

3. **Enqueue a Job**:
   - Under the **Jobs** section, expand `POST /api/v1/jobs/health-check`.
   - Click **Try it out** and then **Execute**.
   - Note the returned `task_id` in the response body:
     ```json
     {
       "task_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
       "status": "queued"
     }
     ```

4. **Inspect Worker Terminal**:
   Watch the Celery worker terminal log execution in real-time:
   ```text
   [INFO/MainProcess] Task app.workers.tasks.health_check_task[...] received
   [INFO/MainProcess] Executing health_check_task [...]
   [INFO/MainProcess] Task app.workers.tasks.health_check_task[...] succeeded in 0.015s
   ```

5. **Poll Job Status**:
   - In Swagger UI, expand `GET /api/v1/jobs/{task_id}`.
   - Click **Try it out**, paste the `task_id`, and click **Execute**.
   - Inspect the completed task payload:
     ```json
     {
       "task_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
       "status": "SUCCESS",
       "ready": true,
       "successful": true,
       "result": {
         "task_name": "health_check_task",
         "task_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
         "status": "completed",
         "timestamp": "2026-10-31T13:40:00.000000Z"
       },
       "error": null
     }
     ```

