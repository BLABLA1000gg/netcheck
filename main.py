from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import dns.resolver
import dns.reversename
import ssl
import socket
import httpx
import asyncio
import ipaddress
import datetime
from typing import Optional
import os

app = FastAPI(title="netcheck API", version="1.0.0")


# ── DNS lookup ────────────────────────────────────────────────────────────────

class DNSResult(BaseModel):
    domain: str
    records: dict[str, list[str]]
    error: Optional[str] = None


@app.get("/api/dns/{domain}", response_model=DNSResult)
async def dns_lookup(domain: str):
    records: dict[str, list[str]] = {}
    error = None
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            error = "Domain does not exist"
            break
        except Exception:
            pass
    return DNSResult(domain=domain, records=records, error=error)


# ── Reverse DNS ───────────────────────────────────────────────────────────────

class ReverseDNSResult(BaseModel):
    ip: str
    hostname: Optional[str] = None
    error: Optional[str] = None


@app.get("/api/rdns/{ip}", response_model=ReverseDNSResult)
async def reverse_dns(ip: str):
    try:
        ipaddress.ip_address(ip)  # validate
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, "PTR", lifetime=5)
        return ReverseDNSResult(ip=ip, hostname=str(answers[0]))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    except Exception as e:
        return ReverseDNSResult(ip=ip, error=str(e))


# ── HTTP check ────────────────────────────────────────────────────────────────

class HTTPResult(BaseModel):
    url: str
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    redirect_url: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    error: Optional[str] = None


@app.get("/api/http")
async def http_check(url: str):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        start = asyncio.get_event_loop().time()
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            r = await client.get(url)
        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        return HTTPResult(
            url=url,
            status_code=r.status_code,
            response_time_ms=round(elapsed, 1),
            redirect_url=str(r.url) if str(r.url) != url else None,
            server=r.headers.get("server"),
            content_type=r.headers.get("content-type", "").split(";")[0],
        )
    except Exception as e:
        return HTTPResult(url=url, error=str(e))


# ── SSL certificate ───────────────────────────────────────────────────────────

class SSLResult(BaseModel):
    host: str
    valid: bool
    issued_to: Optional[str] = None
    issued_by: Optional[str] = None
    expires: Optional[str] = None
    days_remaining: Optional[int] = None
    error: Optional[str] = None


@app.get("/api/ssl/{host}", response_model=SSLResult)
async def ssl_check(host: str):
    host = host.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=10), server_hostname=host
        ) as s:
            cert = s.getpeercert()
        subject = dict(x[0] for x in cert["subject"])
        issuer  = dict(x[0] for x in cert["issuer"])
        expires = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        days = (expires - datetime.datetime.utcnow()).days
        return SSLResult(
            host=host,
            valid=True,
            issued_to=subject.get("commonName"),
            issued_by=issuer.get("organizationName"),
            expires=expires.strftime("%Y-%m-%d"),
            days_remaining=days,
        )
    except ssl.SSLCertVerificationError as e:
        return SSLResult(host=host, valid=False, error=str(e))
    except Exception as e:
        return SSLResult(host=host, valid=False, error=str(e))


# ── Port check ────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB",
}

class PortResult(BaseModel):
    host: str
    port: int
    service: Optional[str] = None
    open: bool
    response_time_ms: Optional[float] = None


class PortScanResult(BaseModel):
    host: str
    resolved_ip: Optional[str] = None
    ports: list[PortResult]
    error: Optional[str] = None


async def check_port(host: str, port: int) -> PortResult:
    try:
        start = asyncio.get_event_loop().time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2
        )
        writer.close()
        elapsed = (asyncio.get_event_loop().time() - start) * 1000
        return PortResult(
            host=host, port=port,
            service=COMMON_PORTS.get(port),
            open=True,
            response_time_ms=round(elapsed, 1),
        )
    except Exception:
        return PortResult(host=host, port=port, service=COMMON_PORTS.get(port), open=False)


@app.get("/api/ports/{host}", response_model=PortScanResult)
async def port_scan(host: str):
    try:
        resolved = socket.gethostbyname(host)
    except Exception as e:
        return PortScanResult(host=host, ports=[], error=str(e))

    results = await asyncio.gather(
        *[check_port(resolved, p) for p in COMMON_PORTS]
    )
    return PortScanResult(
        host=host,
        resolved_ip=resolved,
        ports=sorted(results, key=lambda x: x.port),
    )


# ── IP info ───────────────────────────────────────────────────────────────────

@app.get("/api/ip/{ip}")
async def ip_info(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")
    async with httpx.AsyncClient(timeout=8) as client:
        r = await client.get(f"https://ipapi.co/{ip}/json/")
        return r.json()


# ── Serve frontend ────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return FileResponse("static/index.html")

@app.get("/health")
async def health():
    return {"status": "ok"}
