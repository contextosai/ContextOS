# Framework examples

One runnable example per agent framework, each governing the quickstart's refund
through the framework's own agent loop:

```sh
./examples/frameworks/run.sh <framework>     # e.g. langgraph, openai-agents-js, mastra
```

Without a provider API key each example uses a scripted model, so it runs anywhere;
its README names the key for a real model. The implementation guides, and what every
integration has in common, are in [docs/integrations](../../docs/integrations/README.md).
`_shared/` holds the setup every example uses: admission, the governed tools, the
model-call budget, the refusal text and the closing decision.
