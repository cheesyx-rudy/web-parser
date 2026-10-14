"""Convert common Xray and sing-box proxy JSON objects to share-link URIs locally.

No source config is sent to a third-party conversion API. Unsupported protocols are
skipped explicitly; a successful JSON parse does not imply every outbound has a
portable share-link representation.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Iterable
from urllib.parse import quote, urlencode

PROXY_TYPES = {
    "vless", "vmess", "trojan", "shadowsocks", "ss", "socks", "socks5",
    "http", "hysteria2", "hy2", "tuic", "anytls",
}
WRAPPER_KEYS = ("config", "data", "configs", "items", "nodes", "proxies", "result")


def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off", "none"}
    return bool(value)


def _alpn_text(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(_text(item) for item in value if item is not None and _text(item))
    return _text(value)


def _hostport(host: Any, port: Any) -> str:
    host_s = _text(host).strip()
    if not host_s or port in (None, ""):
        raise ValueError("missing server or port")
    if ":" in host_s and not (host_s.startswith("[") and host_s.endswith("]")):
        host_s = f"[{host_s}]"
    return f"{host_s}:{int(port)}"


def _fragment(tag: Any) -> str:
    tag_s = _text(tag).strip()
    return f"#{quote(tag_s, safe='')}" if tag_s else ""


def _uri(scheme: str, userinfo: str, host: Any, port: Any, params: dict[str, Any] | None = None, tag: Any = "") -> str:
    address = _hostport(host, port)
    query_values: list[tuple[str, str]] = []
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple)):
            if not value:
                continue
            value = ",".join(_text(v) for v in value if v is not None and _text(v) != "")
            if not value:
                continue
        query_values.append((key, _text(value)))
    query = urlencode(query_values, doseq=False, quote_via=quote, safe="")
    return f"{scheme}://{userinfo}@{address}" + (f"?{query}" if query else "") + _fragment(tag)


def _first_host_header(headers: Any) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == "host":
            if isinstance(value, list):
                return _text(value[0]) if value else ""
            return _text(value)
    return ""


def _xray_stream_params(outbound: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    stream = outbound.get("streamSettings")
    if not isinstance(stream, dict):
        stream = {}
    network = _text(stream.get("network"), "tcp").lower() or "tcp"
    params: dict[str, Any] = {"type": network}

    if network == "ws":
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        headers = ws.get("headers") if isinstance(ws.get("headers"), dict) else {}
        params["path"] = ws.get("path") or "/"
        params["host"] = _first_host_header(headers)
        if ws.get("maxEarlyData"):
            params["ed"] = ws["maxEarlyData"]
        if ws.get("earlyDataHeaderName"):
            params["eh"] = ws["earlyDataHeaderName"]
    elif network == "grpc":
        grpc = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        params["serviceName"] = grpc.get("serviceName") or ""
        params["mode"] = "multi" if _truthy(grpc.get("multiMode")) else "gun"
    elif network == "httpupgrade":
        item = stream.get("httpupgradeSettings") if isinstance(stream.get("httpupgradeSettings"), dict) else {}
        params["path"] = item.get("path") or "/"
        params["host"] = item.get("host") or ""
    elif network in {"xhttp", "splithttp"}:
        item = stream.get("xhttpSettings") or stream.get("splithttpSettings")
        item = item if isinstance(item, dict) else {}
        params["type"] = "xhttp"
        params["path"] = item.get("path") or "/"
        params["host"] = item.get("host") or ""
        params["mode"] = item.get("mode") or ""
    elif network == "kcp":
        item = stream.get("kcpSettings") if isinstance(stream.get("kcpSettings"), dict) else {}
        header = item.get("header") if isinstance(item.get("header"), dict) else {}
        params["headerType"] = header.get("type") or "none"
        params["seed"] = item.get("seed") or ""
    elif network == "tcp":
        item = stream.get("tcpSettings") if isinstance(stream.get("tcpSettings"), dict) else {}
        header = item.get("header") if isinstance(item.get("header"), dict) else {}
        header_type = _text(header.get("type"), "none") or "none"
        if header_type.lower() == "http":
            params["headerType"] = "http"
            request = header.get("request") if isinstance(header.get("request"), dict) else {}
            headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
            host = _first_host_header(headers)
            if host:
                params["host"] = host
            path = request.get("path")
            if isinstance(path, list):
                path = path[0] if path else ""
            if path:
                params["path"] = path
        else:
            params["headerType"] = header_type
    elif network == "http":
        item = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        params["path"] = item.get("path") or "/"
        host = item.get("host")
        if isinstance(host, list):
            host = host[0] if host else ""
        params["host"] = host or ""

    security = _text(stream.get("security"), "none").lower() or "none"
    if security not in {"none", "tls", "reality"}:
        security = "none"
    params["security"] = security
    if security == "tls":
        tls = stream.get("tlsSettings") if isinstance(stream.get("tlsSettings"), dict) else {}
        params["sni"] = tls.get("serverName") or ""
        params["alpn"] = tls.get("alpn") or ""
        params["fp"] = tls.get("fingerprint") or ""
        if _truthy(tls.get("allowInsecure")):
            params["allowInsecure"] = "1"
    elif security == "reality":
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        params["sni"] = reality.get("serverName") or ""
        params["fp"] = reality.get("fingerprint") or "chrome"
        params["pbk"] = reality.get("publicKey") or reality.get("public_key") or ""
        params["sid"] = reality.get("shortId") or reality.get("short_id") or ""
        params["spx"] = reality.get("spiderX") or reality.get("spider_x") or ""
    return security, params


def _xray_urls(outbound: dict[str, Any], protocol: str) -> list[str]:
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    tag = outbound.get("tag") or protocol
    if protocol in {"vless", "vmess"}:
        targets = settings.get("vnext")
        if not isinstance(targets, list):
            return []
        security, stream_params = _xray_stream_params(outbound)
        results: list[str] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            users = target.get("users") if isinstance(target.get("users"), list) else []
            for index, user in enumerate(users):
                if not isinstance(user, dict) or not user.get("id"):
                    continue
                name = user.get("email") or user.get("name") or tag
                if len(targets) > 1 or len(users) > 1:
                    name = f"{name}-{index + 1}" if name == tag else name
                if protocol == "vless":
                    params = {"encryption": user.get("encryption") or "none", **stream_params}
                    if user.get("flow"):
                        params["flow"] = user["flow"]
                    results.append(_uri("vless", quote(_text(user["id"]), safe="-._~"), target.get("address"), target.get("port"), params, name))
                else:
                    net = _text(stream_params.get("type"), "tcp")
                    tls_security = security if security == "tls" else ""
                    extra = {}
                    if tls_security:
                        extra["tls"] = "tls"
                    elif security == "reality":
                        extra["tls"] = "tls"
                    vmess_data = {
                        "v": "2", "ps": _text(name), "add": _text(target.get("address")),
                        "port": _text(target.get("port")), "id": _text(user.get("id")),
                        "aid": _text(user.get("alterId"), "0"), "scy": _text(user.get("security"), "auto"),
                        "net": net, "type": _text(stream_params.get("headerType"), "none"),
                        "host": _text(stream_params.get("host")), "path": _text(stream_params.get("path") or stream_params.get("serviceName")),
                        "tls": "tls" if security in {"tls", "reality"} else "",
                        "sni": _text(stream_params.get("sni")), "alpn": _alpn_text(stream_params.get("alpn")),
                        "fp": _text(stream_params.get("fp")),
                    }
                    if stream_params.get("allowInsecure"):
                        vmess_data["allowInsecure"] = _text(stream_params["allowInsecure"])
                    encoded = base64.b64encode(json.dumps(vmess_data, ensure_ascii=False, separators=(",", ":")).encode()).decode()
                    results.append(f"vmess://{encoded}")
        return results

    if protocol in {"trojan", "shadowsocks", "socks", "http"}:
        servers = settings.get("servers")
        if not isinstance(servers, list):
            return []
        results = []
        security, stream_params = _xray_stream_params(outbound)
        for server in servers:
            if not isinstance(server, dict):
                continue
            host, port = server.get("address"), server.get("port")
            name = server.get("email") or tag
            if protocol == "trojan":
                password = server.get("password")
                if password is None:
                    continue
                params = {key: value for key, value in stream_params.items() if key not in {"encryption", "headerType", "flow"}}
                results.append(_uri("trojan", quote(_text(password), safe="-._~"), host, port, params, name))
            elif protocol == "shadowsocks":
                method = server.get("method") or server.get("email")
                password = server.get("password")
                if not method or password is None:
                    continue
                userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
                results.append(f"ss://{userinfo}@{_hostport(host, port)}{_fragment(name)}")
            else:
                users = server.get("users") if isinstance(server.get("users"), list) else [{}]
                for user in users:
                    user = user if isinstance(user, dict) else {}
                    creds = ""
                    if user.get("user") is not None or user.get("pass") is not None:
                        creds = quote(_text(user.get("user")), safe="") + ":" + quote(_text(user.get("pass")), safe="")
                    scheme = "socks" if protocol == "socks" else "http"
                    if creds:
                        # This URI form puts authentication in the authority component.
                        address = _hostport(host, port)
                        results.append(f"{scheme}://{creds}@{address}{_fragment(user.get('email') or name)}")
                    else:
                        results.append(f"{scheme}://{_hostport(host, port)}{_fragment(user.get('email') or name)}")
        return results
    return []


def _singbox_tls_params(outbound: dict[str, Any]) -> dict[str, Any]:
    tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}
    if not _truthy(tls.get("enabled")):
        return {"security": "none"}
    params: dict[str, Any] = {"security": "tls"}
    params["sni"] = tls.get("server_name") or ""
    params["alpn"] = tls.get("alpn") or ""
    if _truthy(tls.get("insecure")):
        params["allowInsecure"] = "1"
    utls = tls.get("utls") if isinstance(tls.get("utls"), dict) else {}
    if _truthy(utls.get("enabled")) and utls.get("fingerprint"):
        params["fp"] = utls["fingerprint"]
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}
    if _truthy(reality.get("enabled")):
        params["security"] = "reality"
        params["pbk"] = reality.get("public_key") or ""
        params["sid"] = reality.get("short_id") or ""
        if not params.get("fp"):
            params["fp"] = "chrome"
    return params


def _singbox_transport_params(outbound: dict[str, Any]) -> dict[str, Any]:
    transport = outbound.get("transport") if isinstance(outbound.get("transport"), dict) else {}
    kind = _text(transport.get("type"), "tcp").lower() or "tcp"
    params: dict[str, Any] = {"type": kind}
    if kind == "ws":
        params["path"] = transport.get("path") or "/"
        params["host"] = _first_host_header(transport.get("headers"))
        if transport.get("max_early_data"):
            params["ed"] = transport["max_early_data"]
        if transport.get("early_data_header_name"):
            params["eh"] = transport["early_data_header_name"]
    elif kind == "grpc":
        params["serviceName"] = transport.get("service_name") or ""
        params["mode"] = "multi" if _truthy(transport.get("multi_mode")) else "gun"
    elif kind == "httpupgrade":
        params["path"] = transport.get("path") or "/"
        params["host"] = transport.get("host") or ""
    elif kind in {"http", "h2"}:
        params["type"] = "http"
        params["path"] = transport.get("path") or "/"
        host = transport.get("host")
        if isinstance(host, list):
            host = host[0] if host else ""
        params["host"] = host or ""
    return params


def _singbox_urls(outbound: dict[str, Any], protocol: str) -> list[str]:
    host, port = outbound.get("server"), outbound.get("server_port") or outbound.get("port")
    if not host or not port:
        return []
    tag = outbound.get("tag") or protocol
    tls = _singbox_tls_params(outbound)
    transport = _singbox_transport_params(outbound)

    if protocol == "vless":
        uuid = outbound.get("uuid")
        if not uuid:
            return []
        params = {"encryption": outbound.get("packet_encoding") == "xudp" and "none" or "none", **tls, **transport}
        if outbound.get("flow"):
            params["flow"] = outbound["flow"]
        return [_uri("vless", quote(_text(uuid), safe="-._~"), host, port, params, tag)]

    if protocol == "vmess":
        uuid = outbound.get("uuid")
        if not uuid:
            return []
        vmess_data = {
            "v": "2", "ps": _text(tag), "add": _text(host), "port": _text(port),
            "id": _text(uuid), "aid": _text(outbound.get("alter_id"), "0"),
            "scy": _text(outbound.get("security"), "auto"), "net": _text(transport.get("type"), "tcp"),
            "type": _text(transport.get("headerType"), "none"), "host": _text(transport.get("host")),
            "path": _text(transport.get("path") or transport.get("serviceName")),
            "tls": "tls" if tls.get("security") in {"tls", "reality"} else "",
            "sni": _text(tls.get("sni")), "alpn": _alpn_text(tls.get("alpn")), "fp": _text(tls.get("fp")),
        }
        encoded = base64.b64encode(json.dumps(vmess_data, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return [f"vmess://{encoded}"]

    if protocol == "trojan":
        password = outbound.get("password")
        if password is None:
            return []
        params = {**tls, **transport}
        return [_uri("trojan", quote(_text(password), safe="-._~"), host, port, params, tag)]

    if protocol in {"shadowsocks", "ss"}:
        method, password = outbound.get("method"), outbound.get("password")
        if not method or password is None:
            return []
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return [f"ss://{userinfo}@{_hostport(host, port)}{_fragment(tag)}"]

    if protocol in {"socks", "socks5", "http"}:
        username = outbound.get("username") or ""
        password = outbound.get("password") or ""
        credentials = f"{quote(_text(username), safe='')}:{quote(_text(password), safe='')}@" if username or password else ""
        scheme = "socks" if protocol in {"socks", "socks5"} else "http"
        return [f"{scheme}://{credentials}{_hostport(host, port)}{_fragment(tag)}"]

    if protocol in {"hysteria2", "hy2"}:
        password = outbound.get("password") or outbound.get("auth")
        if password is None:
            return []
        userinfo = quote(_text(password), safe="-._~")
        params = {"sni": tls.get("sni"), "alpn": tls.get("alpn"), "insecure": "1" if tls.get("allowInsecure") else None}
        obfs = outbound.get("obfs") if isinstance(outbound.get("obfs"), dict) else {}
        if obfs.get("type"):
            params["obfs"] = obfs["type"]
            params["obfs-password"] = obfs.get("password") or ""
        return [_uri("hysteria2", userinfo, host, port, params, tag)]

    if protocol == "tuic":
        uuid, password = outbound.get("uuid"), outbound.get("password")
        if not uuid or password is None:
            return []
        params = {"sni": tls.get("sni"), "alpn": tls.get("alpn") or "h3", "congestion_control": outbound.get("congestion_control") or "cubic", "udp_relay_mode": outbound.get("udp_relay_mode") or "native"}
        if tls.get("allowInsecure"):
            params["allowInsecure"] = "1"
        return [_uri("tuic", f"{quote(_text(uuid), safe='-._~')}:{quote(_text(password), safe='-._~')}", host, port, params, tag)]

    if protocol == "anytls":
        password = outbound.get("password")
        if password is None:
            return []
        params = {"sni": tls.get("sni"), "alpn": tls.get("alpn"), "insecure": "1" if tls.get("allowInsecure") else None}
        return [_uri("anytls", quote(_text(password), safe="-._~"), host, port, params, tag)]

    return []


def _iter_outbounds(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_outbounds(item)
        return
    if not isinstance(payload, dict):
        return

    protocol = _text(payload.get("protocol") or payload.get("type")).lower()
    if protocol in PROXY_TYPES:
        # An Xray outbound has settings; a sing-box outbound has server/server_port.
        if isinstance(payload.get("settings"), dict) or payload.get("server"):
            yield payload
            return

    outbounds = payload.get("outbounds")
    if isinstance(outbounds, list):
        for item in outbounds:
            if isinstance(item, dict):
                yield from _iter_outbounds(item)
        return

    for key in WRAPPER_KEYS:
        if key in payload:
            child = payload[key]
            if isinstance(child, str):
                try:
                    child = json.loads(child)
                except json.JSONDecodeError:
                    continue
            yield from _iter_outbounds(child)


def is_supported_proxy_json(body: str) -> bool:
    try:
        payload = json.loads(body.lstrip("\ufeff").strip())
    except (json.JSONDecodeError, TypeError):
        return False
    return any(True for _ in _iter_outbounds(payload))


def convert_proxy_json_to_urls(body: str) -> list[str]:
    """Convert supported JSON outbounds to normal share links without network calls."""
    try:
        payload = json.loads(body.lstrip("\ufeff").strip())
    except (json.JSONDecodeError, TypeError):
        return []

    result: list[str] = []
    seen: set[str] = set()
    for outbound in _iter_outbounds(payload):
        protocol = _text(outbound.get("protocol") or outbound.get("type")).lower()
        try:
            if isinstance(outbound.get("settings"), dict):
                converted = _xray_urls(outbound, protocol)
            else:
                converted = _singbox_urls(outbound, protocol)
        except (TypeError, ValueError, OverflowError):
            converted = []
        if not converted:
            tag = _text(outbound.get("tag"), protocol)
            print(f"[WARN] Local JSON converter: cannot convert outbound {tag!r} ({protocol or 'unknown'}); skipped")
        for url in converted:
            if url not in seen:
                seen.add(url)
                result.append(url)
    return result
