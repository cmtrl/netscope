# NetScope demo

The example runs against a small HTTP server on your own machine. It shows a
TCP port check, HTTP headers, and a JSON report. DNS enumeration is skipped
because the target is an IP address.

## Videos

These silent, captioned clips were generated from real NetScope output against
the local demo server:

- [Portrait MP4](https://github.com/cmtrl/netscope/raw/refs/heads/main/docs/assets/netscope-demo-x.mp4)
- [Landscape MP4](https://github.com/cmtrl/netscope/raw/refs/heads/main/docs/assets/netscope-demo-landscape.mp4)

## Run it yourself

Install NetScope 1.1.0 or newer in a virtual environment. Start the server:

```bash
netscope-demo
```

In another terminal, with the same environment active:

```bash
netscope http://127.0.0.1:8080 -p 8080 -o json --output-file demo.json
```

Expected output:

- Port 8080 is open, and HTTP returns 200.
- CSP is present; X-Frame-Options is missing on purpose.
- HSTS is not applicable to plain HTTP.
- The report is saved as `demo.json`.

The server listens only on `127.0.0.1`. Stop it with Ctrl+C. If 8080 is already
in use, start it with `--port 8081` and change the URL and `-p` value to match.

To print a short summary from the report:

```bash
python -c "import json; r=json.load(open('demo.json', encoding='utf-8')); print(json.dumps(r['summary'], indent=2))"
```

## Recording

A 25–30 second clip is enough for this example. Capture the terminal window at
1280×720 and 30 fps, with the font large enough to read on a phone.

Show the command, pause on the open port and HTTP response, then scroll to the
header checks. Finish with the JSON summary and repository URL. Do the install
and server setup before recording.

The clip works with captions and no audio. If you add your voice, explain what
you're checking and what the results mean. The missing header is a presence
check, not a confirmed vulnerability.

Export as MP4 and watch it once before posting. In OBS, you can convert an MKV
recording using **File → Remux Recordings**.
