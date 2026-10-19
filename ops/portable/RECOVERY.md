# SlipNet Portable Recovery Notes

This directory intentionally contains only public-safe recovery tooling.

Do not commit generated portable bundles, live Xray JSON, UUIDs, TLS private keys,
API tokens, provider credentials, or current live infrastructure inventory.

A live server can generate a private recovery bundle with `export-live.sh`.
That bundle must be stored encrypted outside the server if disaster recovery from
total server loss is required.

Before any cutover, run the corresponding `validate.sh` and complete a real
end-to-end application test. Keep the old server available until the soak window
is complete.
