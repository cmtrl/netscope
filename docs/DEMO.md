# Local example

NetScope includes a small HTTP server for trying the tool on your own machine.
It listens only on `127.0.0.1`.

Start the server in one terminal:

```bash
netscope-demo
```

In a second terminal, with NetScope available:

```bash
netscope http://127.0.0.1:8080 -p 8080 -o json --output-file demo.json
```

You should see port 8080 open, HTTP 200, and CSP present. The server deliberately
leaves out X-Frame-Options to show the missing-header result. HSTS doesn't apply
to plain HTTP, and DNS enumeration is skipped for the IP target.

The report is saved to `demo.json`. To inspect its summary:

```bash
python -c "import json; r=json.load(open('demo.json', encoding='utf-8')); print(json.dumps(r['summary'], indent=2))"
```

If 8080 is busy, use `netscope-demo --port 8081` and change the scan URL and
`-p` value to 8081. Stop the server with Ctrl+C.

See the [reference](REFERENCE.md) for the meaning of each result and JSON field.
