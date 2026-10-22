# HookReplay

Replay a captured signed GitHub webhook, then replay it again with only `X-GitHub-Delivery` changed. Read a JSON state field after each request. GitHub signs the request body, while the delivery ID is a separate header.

Supply raw HTTP/1.1 requests with CRLF line endings: a signed POST and a bodyless GET that reads the effect of that POST. The POST must contain one `X-Hub-Signature-256` and one `X-GitHub-Delivery` header. Keep the captured request file private.

```sh
python3 hookreplay.py --origin https://receiver.example --request delivery.http --readback state.http --field processed --out report.json
```

The report contains response statuses, body hashes, and state changes for the first delivery, exact replay, and changed-ID replay. It does not contain request headers, response bodies, or the delivery IDs. Integer state fields also get a per-step delta. A changed state is evidence only when the readback belongs to the same test event and no other writer is active. The tool sends no requests until both input files pass local validation.

Use `--new-id` to choose a reproducible replacement ID. For queued receivers, `--wait 2` delays each readback by two seconds. `--insecure` accepts a lab TLS certificate.
