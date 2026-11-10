# Recording a NetScope demo for X

Use the local fixture below so the result is repeatable. It is a real HTTP
server and a real scan of your machine. It demonstrates TCP, HTTP headers, and
JSON export. It does not demonstrate external DNS enumeration.

## 1. Prepare before recording

Open a clean terminal, enable Do Not Disturb, and close unrelated windows.
Use a dark theme and a readable monospace font, around 22–26 px. Aim for a
1280×720 recording with roughly 100 terminal columns. Test the result at phone
size. Prefer clear text over fitting every line into one shot.

Create a virtual environment and install the released version:

```bash
python -m venv .venv
```

Activate on macOS/Linux:

```bash
source .venv/bin/activate
```

Or on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Then:

```bash
python -m pip install --upgrade cmtrl-netscope
netscope --version
```

The URL, custom ports, and local demo commands require version 1.1.0 or newer.

## 2. Start the local server

In terminal A, with the virtual environment active:

```bash
netscope-demo
```

Leave it running. It binds only to `127.0.0.1:8080`. If that port is busy, use
`netscope-demo --port 8081` and change both the scan URL and `-p` to 8081.

In terminal B, activate the same virtual environment. Run the following once
before recording so you know what to expect:

```bash
netscope http://127.0.0.1:8080 -p 8080 -o json --output-file demo.json
```

Expected results:

- TCP 8080 is open.
- HTTP returns 200 and identifies the server as NetScope-Demo.
- CSP is present; X-Frame-Options is deliberately missing in this fixture.
- HSTS is not applicable on plain HTTP.
- DNS is skipped because the target is an IP address.
- A JSON file is saved.

This is a header-presence demonstration. A missing X-Frame-Options header alone
is not proof of a vulnerability, especially where CSP offers framing protection.

## 3. Record a 25–30 second clip

Use OBS or the screen recorder already on your computer. In OBS:

1. Add a Window Capture source for terminal B; use Screen Capture if your OS
   does not offer that source.
2. Set the canvas and output to 1280×720 at 30 fps. Crop away unrelated desktop
   space so the text fills most of the frame.
3. For a silent clip, disable microphone and desktop audio.
4. Record locally. If recording as MKV, use File → Remux Recordings to export MP4.
5. Watch the exported file from start to finish before uploading it.

A simple shot list:

| Time | Screen | Caption |
| --- | --- | --- |
| 0–3 s | Show the scan command | Check a local web app from the terminal |
| 3–11 s | Run it; pause on the port and HTTP result | TCP port + HTTP response |
| 11–18 s | Scroll to security-header checks | Header presence, not a security score |
| 18–24 s | Show a compact JSON summary | Save results for scripts |
| 24–28 s | Show the install command and repository URL | pip install cmtrl-netscope |

For the JSON shot, use this one-line command (it works in Bash and PowerShell):

```bash
python -c "import json; r=json.load(open('demo.json', encoding='utf-8')); print(json.dumps({'target':r['target'],'summary':r['summary']}, indent=2))"
```

Don't dump the full report into the recording; it scrolls past too quickly.
Record the run normally, then trim setup and pauses. Keep enough time for
viewers to read each result. End with `github.com/cmtrl/netscope` visible.

## 4. Voice or no voice?

For a first post, a silent clip with short captions is enough. The tool should
make sense with the sound off. Music is optional; a clean silent clip works.

If you want to talk, record your own short voiceover after the screen recording:

> This is NetScope, a Python CLI I'm working on. Here I'm checking a local web
> app: it shows the open port, HTTP response, and missing headers, then saves a
> JSON report. It's on GitHub and PyPI. I'd appreciate feedback from anyone who
> tries it.

Speak at your normal pace. Captions should still explain the clip without audio.

## 5. Post it

Upload the MP4 directly to your post and use text such as:

> First public Python project: NetScope.
>
> DNS records, TCP port checks, HTTP headers, and JSON export in one CLI.
>
> Install: pip install cmtrl-netscope
> Code: https://github.com/cmtrl/netscope
>
> If you try it, what would make it more useful for you?

If that is too long for your account's post limit, put the repository link in a
reply and keep the main post focused on the video and install command.

For accessibility, include a plain-text description in your post or reply:
"Terminal demo of NetScope scanning a local HTTP fixture, displaying an open
port and security-header checks, then showing a JSON summary."

## 6. Get useful feedback

Start with a few people who work with Python, local web apps, or Linux tooling.
Ask each tester which OS they use, whether installation worked, and one thing
that was confusing. Link them to the bug-report form in the repository.

Share the project in relevant communities where project posts are welcome.
Explain the use case and respond to the feedback. Turn a reproduced bug into a
small fix, test, and changelog entry. Make a follow-up post when a meaningful
improvement is released.
