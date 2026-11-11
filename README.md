# OpenJules — Autonomous Sandboxed Coding Agent Service

OpenJules is an open-source, asynchronous, cloud-agnostic equivalent of Google Jules.
The system receives tasks from **GitHub issues/webhooks** or **Radicle peer-to-peer repositories (`rad:<rid>`)**, boots an isolated container sandbox (Docker-in-Docker / DinD), coordinates concurrent agents working on the same repository via **Keystone Polyphony**, executes an **Adaptive Agent Harness (Propose–Probe–Compose loop)** with **cloud or self-hosted LLMs (vLLM, llama.cpp, Ollama)**, and pushes the verified diff back as a **GitHub Pull Request** or **Radicle Patch**.

## Managed deployment with ZPM

Use the [managed service](docs/managed-service.md) for ZPM repository capacity.
It connects the durable worker lifecycle to Polyphony's authenticated canonical
authority and an [isolated Docker runtime](docs/managed-docker-runtime.md).
The supported baseline executes one approved root command per immutable worker,
preserves capture before release, and recovers delivery intents after restart.
Source snapshots contain only the approved commit's objects; ignored host files
and local Git configuration are excluded.

An explicit [host cleanup command](docs/managed-docker-runtime.md#explicit-host-cleanup)
can remove a qualified executed worker's owned Docker resources after complete
root/child canonical capture. It retains host archives and journals, refuses
legacy or uncertain creations, and requires the managed service to be stopped.
Resources remain retained by default.

An optional [coding agent and model broker](docs/managed-model-broker.md) connects
that root execution to an explicitly configured provider. The broker retains
provider credentials on the trusted host, binds requests to canonical permission
and enforces shared call/token limits. Worker networking remains disabled.
The default profile makes no model calls. Explicitly approved profiles can use
[one level of bounded child agents](docs/managed-children.md) inside the same
worker, with distinct UIDs, shared model limits and verified child capture before
root release. Child expiry or cancellation retires the whole worker. Forge
publication remains outside this managed service.

An explicit child `outcome_protocol: initial-v1` profile can retain completed,
declined, clarification-needed or failed self-reports for the original private
instruction. The parent can read provisional reports, and final capture binds
them to canonical child records for reconnect. This requires the paired
Polyphony capability and the approved image; it adds no execution permission or
second instruction round. See the [outcome contract](docs/managed-children.md#explicit-initial-instruction-outcomes).

CI qualifies execution, recovery and the model transport against deterministic
provider fixtures. A configured live provider and semantic task quality require
their own qualification. The older webhook, in-memory collaboration and DinD
paths described below do not satisfy this managed contract and are never used
as a readiness fallback.

Standalone legacy PR feedback refuses the branch shape and provenance marker
produced by [managed publication](docs/managed-publication.md), including custom
publication prefixes. Those feedback operations cannot enter its direct
sandbox, model and push loop. Ordinary standalone review remains available; the
[review boundary](docs/managed-service.md#legacy-pr-review-boundary) documents
the conservative refusal cases and remaining ingress limits.

---

## Architecture Overview

```
          GitHub Webhook                                Radicle Node / Webhook
   (issue labeled openjules:run)                     (issue labeled openjules:run)
                 │                                                 │
                 ▼                                                 ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │                 OpenJules API (FastAPI Control Plane)            │
        │          /api/webhook (GitHub)   |   /api/radicle/webhook        │
        └─────────────────────────────────┬────────────────────────────────┘
                                          │
                                          ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │            Pluggable Task Dispatcher & Worker                    │
        │      (BackgroundTasksDispatcher / RadicleNodePoller)             │
        └─────────────────────────────────┬────────────────────────────────┘
                                          │
                                          ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │               Keystone Polyphony Swarm Coordination              │
        │         (Repo-Scoped Swarm Key, Batons, Thoughts, Backlog)       │
        └─────────────────────────────────┬────────────────────────────────┘
                                          │
                                          ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │                     Sandbox Manager (Docker-py)                  │
        │           Mounts /workspace, sets 4G RAM & 2 CPU quota           │
        └─────────────────────────────────┬────────────────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
     ┌─────────────────────────┐                     ┌─────────────────────────┐
     │  Adaptive Agent Harness │                     │   Pluggable Forge Layer │
     │  Propose-Probe-Compose  │                     │   GitHubProvider        │
     │  EXPERIENCE.md Memory   │                     │   RadicleProvider       │
     └─────────────────────────┘                     └─────────────────────────┘
```

The system comprises 4 core architectural phases plus multi-forge, multi-agent swarm, self-hosted LLM, and adaptive harness support:
1. **Repository Configuration & Sandbox Runtime (`src/sandbox/`)**:
   - `src/sandbox/config.py`: Schema parser for `.openjules.yaml` defining base image, setup scripts, test commands, timeouts, env vars, LLM parameters, and adaptive harness settings.
   - `src/sandbox/docker_driver.py`: `SandboxManager` handling container spawning with resource limits (`mem_limit="4g"`, `nano_cpus=2000000000`), workspace mounting, credential injection, command streaming, and strict `try...finally` cleanup.
2. **Adaptive Agent Harness & Two-Stage Engine (`src/harness/` & `src/agent/`)**:
   - `src/harness/adaptive_engine.py`: Self-contained, adaptive harness implementing the **Propose–Probe–Compose** cycle.
     - **Inner-Loop Adaptation (Task-Level)**: Proposes dynamic guardrails and diagnostic probe commands when verification tests fail, probing them in the sandbox before retrying fixes.
     - **Outer-Loop Adaptation (Harnessing-Level)**: Distills lessons learned from successful runs into `EXPERIENCE.md`, compounding repository-specific rules across all future tasks.
   - `src/agent/tools.py`: Safe tools executing directly inside the sandbox: `read_file`, `write_file`, `apply_patch` (unified diff + search/replace block support), `run_command`, `list_files`.
   - `src/agent/engine.py`:
     - **Step A (Planning Phase)**: Injects historical experience from `EXPERIENCE.md` and generates structured JSON plan (`rationale`, `target_files`, `planned_tests`, `action_steps`).
     - **Step B (Action Loop)**: Stateful ReAct loop with turn limit. Native OpenAI function calling with automatic prompt-guided JSON fallback for local LLMs lacking tool calling schemas.
     - **Step C (Verification)**: Automatically executes `config.test_command` with an adaptive fix loop if tests fail.
3. **Keystone Polyphony Multi-Agent Swarm (`src/polyphony/`)**:
   - Auto-subscribes all agents targeting the same repo to the repo's Polyphony choir using deterministic `SWARM_KEY` derivation (`keystone-polyphony-v1:<repo>`).
   - **Baton Mutex Locks**: Prevents duplicate concurrent runs (`task:{issue_id}`) and coordinates file modifications (`file:{path}`).
   - **Liminal Space**: Broadcasts thoughts, status changes (`planning`, `busy`, `verifying`, `idle`), and audit logs.
   - **Swarm Backlog**: Synchronizes task progress across decentralized nodes.
4. **Pluggable Forge Layer (`src/forge/` & `src/git_manager/`)**:
   - `src/forge/base.py`: Abstract `ForgeProvider` interface.
   - `src/forge/github.py`: GitHub App and PAT integration via PyGithub.
   - `src/forge/radicle.py`: Radicle integration supporting the `rad` CLI (`rad clone`, `rad patch open`) and Radicle Node HTTP API.
   - `src/git_manager/lifecycle.py`: Task branch management (`openjules/task-{issue_id}-{slug}`), Conventional Commits, diff calculation, and PR/Patch summary generation.
5. **Control Plane & Background Task Workers (`src/api/` & `src/worker/`)**:
   - `src/api/webhook.py`: FastAPI endpoints for GitHub HMAC-SHA256 webhooks and Radicle webhook events.
   - `src/worker/dispatcher.py`: Extensible `TaskDispatcher` interface.
   - `src/worker/radicle_poller.py`: Background poller for local or self-hosted Radicle nodes (`rad:<rid>`).
   - `src/worker/executor.py`: End-to-end task runner opening PRs/Patches and posting status comments.

---

## Quickstart

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- GitHub App or Personal Access Token (for GitHub)
- Radicle node / CLI (for decentralized Radicle collaboration)
- LLM inference: OpenAI, Anthropic, Gemini, or a self-hosted server (**vLLM**, **llama.cpp**, **Ollama**)

### 1. Local Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/openjules.git
cd openjules

# Install dependencies
pip install -r requirements-dev.txt

# Run test suite
pytest
```

### 2. Running with Docker Compose

OpenJules provides flexible compose profiles for all backends:

```bash
# 1. Standard mode (GitHub + OpenJules DinD + Cloud API keys)
docker compose up -d

# 2. Multi-forge mode with self-hosted Radicle Node
docker compose --profile radicle up -d

# 3. Swarm mode with Keystone Polyphony MQTT broker
docker compose --profile swarm up -d

# 4. Self-hosted inference with vLLM
docker compose --profile vllm up -d

# 5. Lightweight inference with llama.cpp server
docker compose --profile llamacpp up -d
```

Check health:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"openjules","forges":["github","radicle"]}
```

---

## Adaptive Agent Harness (Harness² Paradigm)

In autonomous agent workflows, an agent is:
$$\text{Agent} = \text{Foundation Model} + \text{Harness}$$

OpenJules keeps model weights frozen while dynamically optimizing the **Harness**:
1. **Inner Loop (Task Adaptation)**:
   - When a test verification fails, the harness analyzes the execution trace and generates targeted guardrails and probe commands (`propose_harness_adaptation`).
   - The probe commands run inside the sandbox, and the empirical findings are fed back to guide the next fix attempt.
2. **Outer Loop (Compounded Experience)**:
   - On every verified task, successful architectural strategies and discovered guardrails are committed to `EXPERIENCE.md`.
   - Subsequent tasks automatically read `EXPERIENCE.md` during Step A planning, starting with accumulated project context.

---

## Self-Hosted LLMs (vLLM, llama.cpp, Ollama)

OpenJules natively connects to any OpenAI-compatible inference endpoint:

### Configuration via Environment Variables

```bash
# Connect to vLLM
export LLM_API_BASE="http://localhost:8001/v1"
export LLM_MODEL="openai/Qwen/Qwen2.5-Coder-7B-Instruct"
export LLM_API_KEY="EMPTY"

# Connect to llama.cpp server
export LLM_API_BASE="http://localhost:8081/v1"
export LLM_MODEL="gpt-3.5-turbo"
export LLM_API_KEY="EMPTY"

# Connect to Ollama
export LLM_API_BASE="http://localhost:11434/v1"
export LLM_MODEL="ollama/codellama"
export LLM_API_KEY="ollama"
```

### Configuration via Repository (`.openjules.yaml`)

```yaml
llm:
  model: "Qwen/Qwen2.5-Coder-7B-Instruct"
  api_base: "http://vllm:8000/v1"
  api_key: "EMPTY"
  temperature: 0.2
  max_tokens: 4096

harness:
  adaptive: true
  experience_path: "EXPERIENCE.md"
  inject_experience: true
```

---

## Keystone Polyphony Integration (https://github.com/LokiMetaSmith/keystone-polyphony)

Every agent operating on the same repository automatically joins that repository's Polyphony:
- **Repo-Scoped Anchoring**: The `SWARM_KEY` is derived deterministically from the repository name or Radicle RID, partitioning coordination cleanly.
- **Mutex Batons**: Agents acquire `task:{issue_id}` on startup and `file:{path}` during planning, preventing race conditions or conflicting code changes.
- **Liminal Thoughts Stream**: Real-time progress thoughts stream into the shared mesh.

---

## Radicle Integration Guide (https://radicle.dev)

OpenJules natively supports Radicle peer-to-peer code collaboration:
- **Repository IDs (`rad:<rid>`)**: Clones and works on decentralized repos without a centralized server.
- **Radicle Patches**: Changes are proposed via `rad patch open` rather than GitHub PRs.
- **Dual Triggers**: Webhooks (`POST /api/radicle/webhook`) and background polling (`RadicleNodePoller`).

---

## Architecture Background & Philosophy

OpenJules embraces the **frozen model + adaptive harness** philosophy:
- **Strict Sandbox Boundary**: Every task is constrained to an isolated container with deterministic resource limits (`4g` RAM, `2 CPUs`), ephemeral storage, and guaranteed `try...finally` teardown.
- **Adaptive Harnessing**: Dynamic guardrail generation and persistent `EXPERIENCE.md` library ensure continuous learning without retraining.
- **Model Agnostic & Self-Hosted**: Seamlessly swaps between frontier cloud APIs and offline, self-hosted models (vLLM, llama.cpp, Ollama).
- **Keystone Polyphony Swarm**: Coordinates multiple agents working asynchronously on the same repo using RTOS-inspired mutex batons and shared liminal context.
- **Decentralized & Multi-Forge**: Pluggable forge layer decouples the agent core from any single centralized platform, natively powering both GitHub and Radicle p2p networks.
