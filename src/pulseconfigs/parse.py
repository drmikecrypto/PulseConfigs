from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlparse

from pulseconfigs.models import SCHEME_TO_PROTOCOL, ProxyConfig

_URI_RE = re.compile(
    r"(?P<uri>(?:vless|vmess|trojan|ss|socks5?|hysteria2|hy2|tuic|anytls|wg|wireguard)://[^\s<>\"']+)",
    re.IGNORECASE,
)


def _b64decode_padded(data: str) -> bytes:
    s = data.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s, validate=False)


def maybe_decode_subscription_body(body: str) -> str:
    """Return plain share-link text; decode base64 bodies when needed."""
    text = body.strip()
    if not text:
        return ""
    if "://" in text or text.lstrip().startswith("proxies:"):
        return text
    # Try base64 of newline-separated links
    try:
        decoded = _b64decode_padded(re.sub(r"\s+", "", text)).decode("utf-8", errors="ignore")
        if "://" in decoded or decoded.lstrip().startswith("{"):
            return decoded
    except Exception:
        pass
    return text


def _first_q(qs: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for k in keys:
        vals = qs.get(k) or qs.get(k.lower())
        if vals and vals[0] != "":
            return unquote(vals[0])
    return default


def _parse_vmess(uri: str) -> ProxyConfig | None:
    raw = uri.strip()
    payload = raw.split("://", 1)[1]
    # Query-style vmess://uuid@host:port?...
    if "@" in payload and not payload.startswith("ey"):
        return _parse_standard_uri(raw, force_scheme="vmess")
    try:
        data = json.loads(_b64decode_padded(payload).decode("utf-8"))
    except Exception:
        return None
    host = str(data.get("add") or data.get("host") or "")
    try:
        port = int(data.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if not host or not (1 <= port <= 65535):
        return None
    uuid = str(data.get("id") or "")
    security = str(data.get("tls") or data.get("security") or "").lower()
    if security in {"1", "true"}:
        security = "tls"
    network = str(data.get("net") or data.get("type") or "tcp").lower()
    remark = str(data.get("ps") or data.get("remark") or "")
    params = {str(k): str(v) for k, v in data.items() if v is not None}
    params["id"] = uuid
    return ProxyConfig(
        raw=raw,
        protocol="vmess",
        host=host,
        port=port,
        remark=remark,
        security=security,
        network=network,
        flow=str(data.get("flow") or ""),
        pbk=str(data.get("pbk") or ""),
        sid=str(data.get("sid") or ""),
        sni=str(data.get("sni") or data.get("host") or ""),
        fingerprint=str(data.get("fp") or ""),
        allow_insecure=str(data.get("allowInsecure") or data.get("insecure") or "0") in {"1", "true", "True"},
        params=params,
    )


def _parse_ss(uri: str) -> ProxyConfig | None:
    raw = uri.strip()
    rest = raw.split("://", 1)[1]
    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        remark = unquote(remark)
    # SIP002 ss://base64(method:pass)@host:port
    # or ss://base64(method:pass@host:port)
    userinfo = ""
    hostport = rest
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        try:
            if ":" not in userinfo:
                userinfo = _b64decode_padded(userinfo).decode("utf-8", errors="ignore")
        except Exception:
            pass
    else:
        try:
            decoded = _b64decode_padded(rest).decode("utf-8", errors="ignore")
            if "@" in decoded:
                userinfo, hostport = decoded.rsplit("@", 1)
            else:
                return None
        except Exception:
            return None
    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    host = host.strip("[]")
    try:
        port = int(port_s.split("?")[0])
    except ValueError:
        return None
    method, password = "", ""
    if ":" in userinfo:
        method, password = userinfo.split(":", 1)
    qs = parse_qs(urlparse("ss://x?" + (hostport.split("?", 1)[1] if "?" in hostport else "")).query)
    plugin = _first_q(qs, "plugin")
    params = {"method": method, "password": password, "id": password}
    if plugin:
        params["plugin"] = plugin
    return ProxyConfig(
        raw=raw,
        protocol="shadowsocks",
        host=host,
        port=port,
        remark=remark,
        security="",
        network=_first_q(qs, "type", "network") or "tcp",
        params=params,
    )


def _parse_standard_uri(uri: str, force_scheme: str | None = None) -> ProxyConfig | None:
    raw = uri.strip()
    # urlparse needs careful handling of non-http schemes
    try:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or 0
    except Exception:
        return None
    scheme = (force_scheme or parsed.scheme or "").lower()
    protocol = SCHEME_TO_PROTOCOL.get(scheme)
    if not protocol:
        return None
    if not host or not port:
        # wireguard / some links may encode differently
        return None
    remark = unquote(parsed.fragment or "")
    qs = parse_qs(parsed.query, keep_blank_values=True)
    params = {k: unquote(v[0]) for k, v in qs.items() if v}
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "") if parsed.password is not None else ""
    if user:
        params.setdefault("id", user)
        params.setdefault("uuid", user)
        if password:
            params["password"] = password
            params["id"] = f"{user}:{password}" if protocol == "tuic" else user
        elif protocol in {"trojan", "anytls", "hysteria2"}:
            params["password"] = user
            params["id"] = user
    security = _first_q(qs, "security", "tls").lower()
    if security in {"1", "true"}:
        security = "tls"
    if protocol == "trojan" and not security:
        security = "tls"
    network = _first_q(qs, "type", "network", "net", default="tcp").lower()
    flow = _first_q(qs, "flow")
    pbk = _first_q(qs, "pbk", "publicKey", "public-key")
    sid = _first_q(qs, "sid", "shortId", "short-id")
    sni = _first_q(qs, "sni", "servername", "host")
    fp = _first_q(qs, "fp", "fingerprint")
    insecure = _first_q(qs, "allowInsecure", "insecure", "skip-cert-verify").lower() in {
        "1",
        "true",
        "yes",
    }
    if protocol == "wireguard":
        params.setdefault("publickey", _first_q(qs, "publickey", "publicKey", "peer"))
    return ProxyConfig(
        raw=raw,
        protocol=protocol,
        host=host,
        port=int(port),
        remark=remark,
        security=security,
        network=network,
        flow=flow,
        pbk=pbk,
        sid=sid,
        sni=sni,
        fingerprint=fp,
        allow_insecure=insecure,
        params=params,
    )


def parse_share_link(uri: str) -> ProxyConfig | None:
    text = uri.strip().strip("`\"'")
    if not text or "://" not in text:
        return None
    # Strip trailing punctuation often found in markdown
    text = text.rstrip(").,;")
    try:
        scheme = text.split("://", 1)[0].lower()
        if scheme == "vmess":
            return _parse_vmess(text)
        if scheme == "ss":
            return _parse_ss(text)
        return _parse_standard_uri(text)
    except Exception:
        return None


def extract_uris(text: str) -> list[str]:
    body = maybe_decode_subscription_body(text)
    found: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" in line and not line.lower().startswith("http"):
            cfg = parse_share_link(line)
            if cfg and cfg.raw not in seen:
                seen.add(cfg.raw)
                found.append(cfg.raw)
            continue
        for m in _URI_RE.finditer(line):
            u = m.group("uri").rstrip(").,;")
            if u not in seen:
                seen.add(u)
                found.append(u)
    # Also scan whole body for embedded URIs
    for m in _URI_RE.finditer(body):
        u = m.group("uri").rstrip(").,;")
        if u not in seen:
            seen.add(u)
            found.append(u)
    return found


def parse_subscription_text(text: str, source_id: str = "") -> list[ProxyConfig]:
    configs: list[ProxyConfig] = []
    for uri in extract_uris(text):
        cfg = parse_share_link(uri)
        if cfg is None:
            continue
        cfg.source_id = source_id
        configs.append(cfg)
    # Clash Meta proxies: lines under proxies: with type:
    body = maybe_decode_subscription_body(text)
    if "proxies:" in body or body.lstrip().startswith("-"):
        configs.extend(_parse_clash_proxies(body, source_id))
    return configs


def _parse_clash_proxies(body: str, source_id: str) -> list[ProxyConfig]:
    """Best-effort Clash YAML scrape without requiring full YAML validity."""
    try:
        import yaml
    except ImportError:
        return []
    try:
        data = yaml.safe_load(body)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return []
    out: list[ProxyConfig] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        link = clash_proxy_to_share_link(p)
        if not link:
            continue
        cfg = parse_share_link(link)
        if cfg:
            cfg.source_id = source_id
            out.append(cfg)
    return out


def clash_proxy_to_share_link(p: dict) -> str | None:
    """Convert a Clash Meta proxy dict into a share link when possible."""
    t = str(p.get("type") or "").lower()
    name = str(p.get("name") or "clash")
    server = str(p.get("server") or "")
    port = p.get("port")
    if not server or not port:
        return None
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return None
    from urllib.parse import quote, urlencode

    def q(**kwargs: object) -> str:
        items = {k: str(v) for k, v in kwargs.items() if v is not None and str(v) != ""}
        return urlencode(items, quote_via=quote)

    if t == "vless":
        uuid = p.get("uuid") or ""
        params = {
            "encryption": p.get("encryption") or "none",
            "security": (p.get("reality-opts") and "reality") or ("tls" if p.get("tls") else "none"),
            "type": p.get("network") or "tcp",
            "sni": (p.get("servername") or (p.get("reality-opts") or {}).get("server-name") or ""),
            "fp": (p.get("client-fingerprint") or ""),
            "flow": p.get("flow") or "",
            "pbk": (p.get("reality-opts") or {}).get("public-key") or "",
            "sid": (p.get("reality-opts") or {}).get("short-id") or "",
            "path": (p.get("ws-opts") or {}).get("path") or p.get("path") or "",
            "host": ((p.get("ws-opts") or {}).get("headers") or {}).get("Host") or "",
            "serviceName": (p.get("grpc-opts") or {}).get("grpc-service-name") or "",
        }
        return f"vless://{uuid}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    if t == "vmess":
        payload = {
            "v": "2",
            "ps": name,
            "add": server,
            "port": port_i,
            "id": p.get("uuid") or "",
            "aid": p.get("alterId") or 0,
            "scy": p.get("cipher") or "auto",
            "net": p.get("network") or "tcp",
            "type": "none",
            "tls": "tls" if p.get("tls") else "",
            "sni": p.get("servername") or "",
            "path": (p.get("ws-opts") or {}).get("path") or "",
            "host": ((p.get("ws-opts") or {}).get("headers") or {}).get("Host") or "",
        }
        b = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        return f"vmess://{b}"
    if t == "trojan":
        password = p.get("password") or ""
        params = {
            "security": "tls" if p.get("tls", True) else "none",
            "type": p.get("network") or "tcp",
            "sni": p.get("sni") or p.get("servername") or "",
            "allowInsecure": "1" if p.get("skip-cert-verify") else "0",
            "path": (p.get("ws-opts") or {}).get("path") or "",
            "host": ((p.get("ws-opts") or {}).get("headers") or {}).get("Host") or "",
        }
        return f"trojan://{quote(str(password))}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    if t in {"ss", "shadowsocks"}:
        method = p.get("cipher") or "aes-128-gcm"
        password = p.get("password") or ""
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port_i}#{quote(name)}"
    if t in {"socks", "socks5"}:
        user = p.get("username") or ""
        password = p.get("password") or ""
        auth = f"{quote(str(user))}:{quote(str(password))}@" if user else ""
        return f"socks5://{auth}{server}:{port_i}#{quote(name)}"
    if t in {"hysteria2", "hy2", "hysteria"}:
        password = p.get("password") or p.get("auth") or ""
        params = {
            "sni": p.get("sni") or "",
            "obfs": p.get("obfs") or "",
            "obfs-password": p.get("obfs-password") or "",
            "insecure": "1" if p.get("skip-cert-verify") else "0",
        }
        return f"hy2://{quote(str(password))}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    if t == "tuic":
        uuid = p.get("uuid") or ""
        password = p.get("password") or ""
        params = {
            "congestion_control": p.get("congestion-controller") or p.get("congestion_control") or "bbr",
            "udp_relay_mode": p.get("udp-relay-mode") or "",
            "sni": p.get("sni") or "",
            "alpn": ",".join(p.get("alpn") or []) if isinstance(p.get("alpn"), list) else (p.get("alpn") or ""),
        }
        return f"tuic://{uuid}:{quote(str(password))}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    if t in {"wireguard", "wg"}:
        private = p.get("private-key") or p.get("private_key") or ""
        params = {
            "publickey": ((p.get("peers") or [{}])[0].get("public-key") if p.get("peers") else None)
            or p.get("public-key")
            or "",
            "address": ",".join(p.get("ip") if isinstance(p.get("ip"), list) else [str(p.get("ip") or "")]),
            "mtu": p.get("mtu") or "",
        }
        return f"wireguard://{quote(str(private))}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    if t == "anytls":
        password = p.get("password") or ""
        params = {"sni": p.get("sni") or "", "insecure": "1" if p.get("skip-cert-verify") else "0"}
        return f"anytls://{quote(str(password))}@{server}:{port_i}?{q(**params)}#{quote(name)}"
    return None
