# Phishing Agent — Claude Agent SDK Runner

Autonomous workflow runner using Claude Agent SDK. Runs Claude as a backend
worker with full tool access and no human-in-the-loop.

## Setup

```bash
pip install claude-code-sdk
npm install -g @anthropic-ai/claude-code
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
cd /app/phishing-agent
python agent_runner.py
```

## How it works

- `query()` spins up the Claude agent loop (same engine as Claude Code CLI)
- `max_turns=20` caps the think-tool-observe cycle
- Async streaming provides real-time visibility into agent reasoning and tool calls
- The SDK handles orchestration: tool execution, context management, retries
