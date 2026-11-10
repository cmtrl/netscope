# A short NetScope demo

Aim for about 25 seconds. Use a large terminal font and a clean window.
Keep notifications and unrelated windows out of the recording.

## Commands

Install from PyPI in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install cmtrl-netscope
```

For a repeatable demo, start a small server in a second terminal:

```bash
python -m http.server 8080 --bind 127.0.0.1
```

Record this in your main terminal:

```bash
netscope --version
netscope -t 127.0.0.1 --timeout 2 -o json --output-file demo.json
python -m json.tool demo.json
```

This shows port 8080 open and a JSON report. Forward DNS is skipped for an IP
address, and HTTP analysis uses 80/443, so the server on 8080 does not produce
HTTP header results. Say that if you explain this demo.

For a fuller demo, use a domain you own or have permission to scan in place of
`127.0.0.1`. A failed request remains visible in the output; keep it in the clip.

## Shot list

- **0–4 seconds:** show the command and target.
- **4–14 seconds:** run it and pause on the results.
- **14–20 seconds:** show the JSON export or one interesting result.
- **20–25 seconds:** show `github.com/cmtrl/netscope`.

OBS or your operating system's screen recorder can capture the terminal. Export
an MP4. Check that the text is readable at phone size before posting.

## Post text

> First public project: NetScope, a Python CLI for DNS records, TCP port checks,
> and HTTP headers. I'm using it to learn async Python and networking, and I'll
> keep improving it as I go. Feedback welcome.
>
> https://github.com/cmtrl/netscope

You can also include the installation command: `pip install cmtrl-netscope`.
