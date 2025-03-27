import asyncio
import json
import uuid
import socket
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile
from fastapi.staticfiles import StaticFiles
from urllib.parse import urlparse
import re
from pathlib import Path
from backend.auth_module import router as auth_router
from fastapi.middleware import Middleware

app = FastAPI()

app.include_router(auth_router)

findings_db = []
scan_sessions = {}

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return ""

def parse_whatweb_output(raw):
    output = {}
    if 'Country[' in raw:
        output['country'] = raw.split('Country[')[1].split(']')[0]
    if 'HTTPServer[' in raw:
        output['http_server'] = raw.split('HTTPServer[')[1].split(']')[0]
    if 'IP[' in raw:
        output['ip'] = raw.split('IP[')[1].split(']')[0]
    return output

@app.websocket("/ws/scan/{scan_type}")
async def websocket_scan(websocket: WebSocket, scan_type: str):
    await websocket.accept()
    scan_id = str(uuid.uuid4())
    scan_sessions[scan_id] = { "websocket": websocket, "procs": [], "data": {} }

    try:
        data = await websocket.receive_json()
        input_value = data.get("domain")

        domains = [input_value] if isinstance(input_value, str) else input_value

        for item in domains:
            if scan_type == "vuln":
                url = item.strip()
                parsed = urlparse(url)
                domain = parsed.netloc or parsed.hostname or url
                await websocket.send_json({ "status": "started", "domain": domain })

                vuln_file = f"/tmp/nuclei_{uuid.uuid4()}.jsonl"
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

                # Run Nuclei and save output to file
                proc = await asyncio.create_subprocess_exec(
                    "nuclei",
                    "-u", url,
                    "-t", "/opt/nuclei-templates/http/vulnerabilities/",
                    "-silent", "-j", "-irr", "-or", "-ot", "-nc", "-ts",
                    "-o", vuln_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                scan_sessions[scan_id]["procs"].append(proc)

                # Stream real-time output
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    clean_line = ansi_escape.sub('', line.decode().strip())
                    await websocket.send_json({ "domain": domain, "output": clean_line })

                await proc.wait()

                # Read final file and store in findings
                vulns = []
                if Path(vuln_file).exists():
                    with open(vuln_file, "r") as f:
                        for line in f:
                            try:
                                vulns.append(json.loads(line))
                            except:
                                vulns.append(line.strip())

                findings_db.append({
                    "domain": domain,
                    "scan_type": "vuln",
                    "results": [],
                    "vulns": vulns
                })

                await websocket.send_json({ "domain": domain, "vulns": vulns })
                await websocket.send_json({ "status": "done", "domain": domain })
                continue

            # BASIC or FULL scan
            await websocket.send_json({ "status": "started", "domain": item })

            # Subfinder
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", item, "-silent",
                stdout=asyncio.subprocess.PIPE
            )
            scan_sessions[scan_id]["procs"].append(proc)
            stdout, _ = await proc.communicate()
            subs = stdout.decode().splitlines()

            results = []
            for sub in subs:
                ip = resolve_ip(sub)
                ports = []
                tech = {}

                if scan_type in ["full"]:
                    # Naabu
                    proc = await asyncio.create_subprocess_exec(
                        "naabu", "-host", ip, "-silent",
                        stdout=asyncio.subprocess.PIPE
                    )
                    scan_sessions[scan_id]["procs"].append(proc)
                    naabu_out, _ = await proc.communicate()
                    ports = naabu_out.decode().splitlines()

                    # WhatWeb
                    proc = await asyncio.create_subprocess_exec(
                        "whatweb", sub,
                        stdout=asyncio.subprocess.PIPE
                    )
                    scan_sessions[scan_id]["procs"].append(proc)
                    ww_out, _ = await proc.communicate()
                    tech = parse_whatweb_output(ww_out.decode())

                result = {
                    "subdomain": sub,
                    "ip": ip,
                    "ports": ports,
                    "tech": tech
                }
                results.append(result)
                await websocket.send_json({ "domain": item, "result": result })

            findings_db.append({
                "domain": item,
                "scan_type": scan_type,
                "results": results,
                "vulns": []
            })

            await websocket.send_json({ "status": "done", "domain": item })

        del scan_sessions[scan_id]

    except WebSocketDisconnect:
        del scan_sessions[scan_id]
    except Exception as e:
        await websocket.send_json({ "status": "error", "detail": str(e) })
        del scan_sessions[scan_id]

@app.websocket("/ws/stop")
async def stop_scan(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_json()
    scan_id = data.get("scan_id")
    if scan_id in scan_sessions:
        for proc in scan_sessions[scan_id]["procs"]:
            try: proc.kill()
            except: pass
        await websocket.send_json({ "status": "stopped" })
        del scan_sessions[scan_id]

@app.get("/findings")
async def get_findings():
    return findings_db

@app.delete("/findings/{domain}")
async def delete_finding(domain: str):
    global findings_db
    findings_db = [f for f in findings_db if f["domain"] != domain]
    return {"status": "deleted"}

@app.get("/export/csv")
async def export_csv():
    from fastapi.responses import StreamingResponse
    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Domain", "Subdomain", "IP", "Ports", "Tech", "Scan Type"])

    for entry in findings_db:
        for res in entry["results"]:
            writer.writerow([
                entry["domain"],
                res["subdomain"],
                res["ip"],
                ", ".join(res.get("ports", [])),
                json.dumps(res.get("tech", {})),
                entry["scan_type"]
            ])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv")

@app.post("/upload-domains")
async def upload_domains(file: UploadFile):
    text = await file.read()
    lines = text.decode().splitlines()
    return {"domains": [l.strip() for l in lines if l.strip()]}

app.mount("/ui", StaticFiles(directory="frontend", html=True), name="frontend")
