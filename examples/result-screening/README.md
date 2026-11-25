# Reference result screener

A small service for ContextOS's result-screening port (`[providers.result_screening]`).
It reads a confirmed effect's output before the agent sees it and redacts, by JSON
pointer, values that look like personal data (e-mail, phone), payment card numbers
(Luhn-checked) or secrets (access key ids, API and bearer tokens); an output carrying a
private key is withheld whole. Everything else passes.

It is **off by default** and **pattern based**: it misses data written in other forms
and can flag lookalikes. Use it to try the port, or as a template for your own
classifier, and measure it on your outputs before relying on it. The runtime fails
closed: if the service fails or answers malformed facts, the output is withheld.

```sh
SCREENER_TOKEN=$(openssl rand -hex 16) python3 examples/result-screening/screener.py --port 7710 --token-env SCREENER_TOKEN
```

```toml
[providers.result_screening]
url = "http://127.0.0.1:7710/"
token_env = "SCREENER_TOKEN"
```

Each verdict other than `pass` is audited as `result_screened` with its pointers and
reason codes (`pii.email`, `pii.phone`, `pci.card_number`, `secret.token`,
`secret.private_key`), never the content. The service never logs outputs.

Tests: `python3 -m unittest discover -s examples/result-screening -p 'test_*.py'`.
