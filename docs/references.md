# Design references

The implementation is original C11 code. Its separation of concerns was
informed by these independently implemented systems:

- [OpenAI Codex sandboxing](https://github.com/openai/codex/tree/main/codex-rs/sandboxing)
- [Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [scode](https://github.com/bindsch/scode)

Maelys does not adopt any of their configuration formats as its wire contract.
The stable boundary in this repository is the canonical MIR binary format;
JSON is only a source representation. Backend configuration and process launch
remain outside the MIR and SandboxPlan compiler.
