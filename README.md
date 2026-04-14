<p align="center">
  <img src="docs/assets/banner.jpg" alt="ØK Mnemosyne Banner" width="100%" />
</p>

# Mnemosyne

**Structured AI memory for professionals. 100% local. Zero cloud. Security-first.**

By [ZerOK Labs](https://zeroklabs.ai) — part of the ØK product suite.

## Install

```
claude plugins install mnemosyne
```

That's it. Zero dependencies. Works immediately.

## What You Get

- **Auto-save** — memories saved on session end, even if the AI forgets
- **Auto-retrieve** — relevant memories injected into every session
- **Self-improvement** — `/gotcha` captures mistakes at the source
- **Session mining** — `/mine-session` extracts learnings from past conversations
- **Memory validation** — L3 anti-poisoning blocks injection attempts
- **Templates** — starter `MEMORY.md`, `identity.txt`, and `memory/` directory

## Optional: Enhanced Retrieval

For 100% retrieval accuracy (vs ~60% with keyword matching), add ok-rag:

```
/mnemosyne-setup-rag
```

This guided setup installs [ok-rag](https://github.com/0K-cool/ok-rag) — a hybrid semantic retrieval engine (vector + BM25 + BGE reranker). Requires Ollama and ~2.5GB disk space.

| Configuration | Retrieval R@5 | Dependencies |
|---|:---:|---|
| mnemosyne alone | ~60% | Zero |
| mnemosyne + ok-rag (core) | ~88% | ~150MB |
| mnemosyne + ok-rag (full) | 100% | ~2.5GB |

Benchmarked on [LongMemEval](https://arxiv.org/abs/2410.10813).

## License

MIT
