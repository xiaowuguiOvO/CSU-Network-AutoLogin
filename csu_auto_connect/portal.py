from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from typing import Optional
import ipaddress
import locale
import os
import socket
import subprocess
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlparse, urlunparse

import urllib3

import requests


_IP_RE = r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"
_WLAN_IP_PARAM_RE = re.compile(r"wlan_user_ip=([^&]+)", re.I)

_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class LoginResult:
    ok: bool
    result: Optional[str] = None
    ret_code: Optional[int] = None
    msg: Optional[str] = None
    msg_decoded: Optional[str] = None
    raw: str = ""


@dataclass(frozen=True)
class PortalDefaults:
    login_style: str  # "lab" | "v4"
    probe_url: str
    login_url: str
    js_version: str
    extra_params: str
    referer: str


_PORTAL_DEFAULTS: dict[str, PortalDefaults] = {
    "lab": PortalDefaults(
        login_style="lab",
        probe_url="http://10.255.254.11/",
        login_url="",
        js_version="3.3.1",
        extra_params="",
        referer="http://10.255.254.11/",
    ),
    "telecom": PortalDefaults(
        login_style="v4",
        probe_url="https://portal.csu.edu.cn/",
        login_url="https://portal.csu.edu.cn:802/eportal/portal/login",
        js_version="4.1.3",
        extra_params="terminal_type=1&lang=zh-cn&v=2102&lang=zh",
        referer="https://portal.csu.edu.cn/",
    ),
    # The following types share the same v4 login style by default.
    "unicom": PortalDefaults(
        login_style="v4",
        probe_url="https://10.1.1.1/",
        login_url="https://10.1.1.1:802/eportal/portal/login",
        js_version="4.1.3",
        extra_params="terminal_type=1&lang=zh-cn&v=2102&lang=zh",
        referer="https://10.1.1.1/",
    ),
    "mobile": PortalDefaults(
        login_style="v4",
        probe_url="https://portal.csu.edu.cn/",
        login_url="https://portal.csu.edu.cn:802/eportal/portal/login",
        js_version="4.1.3",
        extra_params="terminal_type=1&lang=zh-cn&v=2102&lang=zh",
        referer="https://portal.csu.edu.cn/",
    ),
    "campus": PortalDefaults(
        login_style="v4",
        probe_url="https://portal.csu.edu.cn/",
        login_url="https://portal.csu.edu.cn:802/eportal/portal/login",
        js_version="4.1.3",
        extra_params="terminal_type=1&lang=zh-cn&v=2102&lang=zh",
        referer="https://portal.csu.edu.cn/",
    ),
}


def get_portal_defaults(portal_type: str) -> PortalDefaults:
    return _PORTAL_DEFAULTS.get(portal_type, _PORTAL_DEFAULTS["lab"])


def get_all_portal_defaults() -> list[PortalDefaults]:
    return list(_PORTAL_DEFAULTS.values())


def _decode_text(resp: requests.Response) -> str:
    # Prefer declared encoding; portal is usually gb2312/gbk.
    enc = None
    ctype = resp.headers.get("Content-Type", "")
    m = re.search(r"charset=([^;]+)", ctype, re.I)
    if m:
        enc = m.group(1).strip().strip('"').strip("'")

    raw = resp.content or b""
    for e in (enc, "gb18030", "gb2312", "utf-8"):
        if not e:
            continue
        try:
            return raw.decode(e, errors="ignore")
        except LookupError:
            continue
    return raw.decode(errors="ignore")


def _should_verify_tls(url: str) -> bool:
    try:
        host = urlparse(url).hostname
        if not host:
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolved = socket.gethostbyname(host)
                ip = ipaddress.ip_address(resolved)
            except OSError:
                return True
        is_rfc1918 = any(ip in net for net in _RFC1918_NETS)
        return not (is_rfc1918 or ip.is_link_local or ip in _CGNAT_NET)
    except ValueError:
        # Not an IP literal
        return True


def _decode_wlan_user_ip(val: str) -> Optional[str]:
    if not val:
        return None
    raw = unquote_plus(val)
    if _is_candidate_ip(raw):
        return raw
    decoded = try_decode_base64(raw)
    if decoded and _is_candidate_ip(decoded):
        return decoded
    return None


def _is_candidate_wlan_ip(ip: str, allow_private: bool) -> bool:
    if not _is_candidate_ip(ip):
        return False
    if allow_private:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(ip_obj in net for net in _RFC1918_NETS)


def _is_candidate_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if ip_obj.version != 4:
        return False
    if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_multicast:
        return False
    # Accept RFC1918, CGNAT, or globally routable IPv4.
    if any(ip_obj in net for net in _RFC1918_NETS):
        return True
    if ip_obj in _CGNAT_NET:
        return True
    if ip_obj.is_global:
        return True
    return False


def _local_ipv4_for_host(host: str) -> Optional[str]:
    if not host:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((host, 80))
            ip = sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return None
    if ip and _is_candidate_ip(ip):
        return ip
    return None


def _score_ifname(name: str) -> int:
    if not name:
        return 0
    lowered = name.lower()
    score = 0
    if "wlan" in lowered or "wi-fi" in lowered or "wifi" in lowered or "无线" in name:
        score += 100
    if "ethernet" in lowered or "以太网" in name:
        score += 50
    bad_keywords = (
        "vmware",
        "virtual",
        "vbox",
        "vboxnet",
        "hyper-v",
        "vethernet",
        "loopback",
        "radmin",
        "vpn",
        "wireguard",
        "tailscale",
        "zerotier",
        "mihomo",
        "wsl",
        "tunnel",
        "tap",
        "tun",
    )
    if any(k in lowered for k in bad_keywords) or any(k in name for k in ("VMware", "VirtualBox", "Mihomo")):
        score -= 1000
    return score


def _parse_ipconfig_text(output: str) -> tuple[list[dict], list[str]]:
    blocks = []
    macs: list[str] = []
    current = {"name": None, "ips": [], "disconnected": False, "mac": None}
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            if current["name"]:
                blocks.append(current)
            current = {"name": line.strip().rstrip(":"), "ips": [], "disconnected": False, "mac": None}
            continue
        if "媒体已断开连接" in line or "Media disconnected" in line:
            current["disconnected"] = True
        m = re.search(r"IPv4[^:]*:\s*([0-9.]+)", line)
        if m:
            current["ips"].append(m.group(1))
        m = re.search(r"(Physical Address|物理地址)[^:]*:\s*([0-9A-Fa-f:-]+)", line)
        if m:
            mac_raw = m.group(2).replace("-", "").replace(":", "").strip()
            if len(mac_raw) >= 12:
                current["mac"] = mac_raw[:12].upper()
    if current["name"]:
        blocks.append(current)

    candidates = []
    mac_candidates = []
    for block in blocks:
        if block["disconnected"]:
            continue
        score = _score_ifname(block["name"])
        if block.get("mac"):
            mac_candidates.append((score, block["mac"]))
        for ip in block["ips"]:
            if not _is_candidate_ip(ip):
                continue
            if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"):
                score += 10
            candidates.append((score, ip))

    if mac_candidates:
        mac_candidates.sort(reverse=True)
        macs.append(mac_candidates[0][1])

    return blocks, macs


def _probe_ipconfig_ipv4_and_mac() -> tuple[Optional[str], Optional[str]]:
    if os.name != "nt":
        return None, None
    try:
        raw = subprocess.check_output(["ipconfig", "/all"], stderr=subprocess.STDOUT)
    except Exception:
        return None, None

    encodings = [locale.getpreferredencoding(False), "gbk", "cp936", "utf-8"]
    seen = set()
    for enc in encodings:
        if not enc or enc in seen:
            continue
        seen.add(enc)
        try:
            text = raw.decode(enc, errors="ignore")
        except LookupError:
            continue
        blocks, macs = _parse_ipconfig_text(text)
        ip = None
        candidates = []
        for block in blocks:
            if block["disconnected"]:
                continue
            score = _score_ifname(block["name"])
            for ip_candidate in block["ips"]:
                if not _is_candidate_ip(ip_candidate):
                    continue
                if ipaddress.ip_address(ip_candidate) in ipaddress.ip_network("100.64.0.0/10"):
                    score += 10
                candidates.append((score, ip_candidate))
        if candidates:
            candidates.sort(reverse=True)
            ip = candidates[0][1]
        mac = macs[0] if macs else None
        if ip or mac:
            return ip, mac
    return None, None


def probe_ipconfig_ipv4() -> Optional[str]:
    ip, _ = _probe_ipconfig_ipv4_and_mac()
    return ip


def probe_ipconfig_wlan_mac() -> Optional[str]:
    _, mac = _probe_ipconfig_ipv4_and_mac()
    return mac


def probe_wlan_user_ip(
    session: requests.Session,
    probe_url: str,
    timeout_sec: float = 3.0,
    fallback_host: Optional[str] = None,
    allow_private: bool = True,
    only_status: bool = False,
) -> Optional[str]:
    """
    Return wlan_user_ip (external ip) by parsing portal HTML.
    """
    if not only_status:
        if probe_url:
            m0 = _WLAN_IP_PARAM_RE.search(probe_url)
            if m0:
                ip = _decode_wlan_user_ip(m0.group(1))
                if ip and _is_candidate_wlan_ip(ip, allow_private):
                    return ip

    urls: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        if not u:
            return
        if u in seen:
            return
        seen.add(u)
        urls.append(u)

    _add(probe_url)
    portal_bases: list[str] = []
    if probe_url:
        parsed = urlparse(probe_url)
        if parsed.scheme and parsed.hostname:
            base = f"{parsed.scheme}://{parsed.hostname}"
            portal_bases.append(base)
            _add(f"{base}/")
            if parsed.port:
                _add(f"{base}:{parsed.port}/")
                _add(f"{base}:{parsed.port}/eportal/")
                _add(f"{base}:{parsed.port}/eportal/portal/")
            else:
                _add(f"{base}:801/")
                _add(f"{base}:802/")
                _add(f"{base}:801/eportal/")
                _add(f"{base}:802/eportal/")
                _add(f"{base}:801/eportal/portal/")
                _add(f"{base}:802/eportal/portal/")
                portal_bases.append(f"{base}:802")
                portal_bases.append(f"{base}:801")

    # Legacy lab defaults as final fallback.
    _add("http://10.255.254.11/")
    _add("http://10.255.254.11:801/")
    _add("http://10.255.254.11:801/eportal/")

    if not only_status:
        for url in urls:
            if not url:
                continue
            try:
                verify_tls = _should_verify_tls(url)
                r = session.get(url, timeout=timeout_sec, allow_redirects=True, verify=verify_tls)
            except requests.RequestException:
                continue

            # Redirect URL may contain wlan_user_ip.
            if "wlan_user_ip=" in r.url:
                m = _WLAN_IP_PARAM_RE.search(r.url)
                if m:
                    ip = _decode_wlan_user_ip(m.group(1))
                    if ip and _is_candidate_wlan_ip(ip, allow_private):
                        return ip

            text = _decode_text(r)

            # Dr.COM pages often expose lip/v4ip variables.
            for pat in (
                rf"lip\s*=\s*'{_IP_RE}'",
                rf"v4ip\s*=\s*'{_IP_RE}'",
                rf"wlan_user_ip\s*=\s*{_IP_RE}",
                rf"wlan_user_ip=({_IP_RE})",
                rf"user_ip\s*=\s*'{_IP_RE}'",
            ):
                mm = re.search(pat, text, re.I)
                if mm:
                    # last group is ip
                    candidate = mm.group(mm.lastindex or 1)
                    ip = _decode_wlan_user_ip(candidate) or candidate
                    if _is_candidate_wlan_ip(ip, allow_private):
                        return ip

            # Base64-encoded wlan_user_ip is also common in v4 portals.
            m2 = re.search(r"wlan_user_ip\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
            if m2:
                ip = _decode_wlan_user_ip(m2.group(1))
                if ip and _is_candidate_wlan_ip(ip, allow_private):
                    return ip

    # Try loadConfig endpoints (common in Dr.COM v4 portals)
    if portal_bases and not only_status:
        ts = int(time.time() * 1000)
        callback = f"dr{ts}"
        load_paths = (
            "/eportal/portal/loadConfig",
            "/eportal/portal/page/loadConfig",
            "/eportal/loadConfig",
            "/portal/loadConfig",
        )
        for base in portal_bases:
            for path in load_paths:
                url = f"{base}{path}?callback={callback}"
                try:
                    verify_tls = _should_verify_tls(url)
                    r = session.get(url, timeout=timeout_sec, allow_redirects=True, verify=verify_tls)
                except requests.RequestException:
                    continue
                text = _decode_text(r)
                data = _parse_jsonp(text)
                if not isinstance(data, dict):
                    continue
                for key in ("wlan_user_ip", "v4ip", "user_ip", "ip"):
                    val = data.get(key)
                    if isinstance(val, str):
                        ip = _decode_wlan_user_ip(val) or val
                        if _is_candidate_wlan_ip(ip, allow_private):
                            return ip

    # Some lab portals expose wlan_user_ip via chkstatus JSONP.
    if portal_bases:
        ts = int(time.time() * 1000)
        callback = f"dr{ts}"
        status_paths = (
            "/eportal/portal/chkstatus",
            "/eportal/chkstatus",
            "/portal/chkstatus",
            "/chkstatus",
            "/drcom/chkstatus",
            "/eportal/portal/chksatus",
            "/eportal/chksatus",
            "/portal/chksatus",
            "/chksatus",
            "/drcom/chksatus",
        )
        for base in portal_bases:
            for path in status_paths:
                sep = "&" if "?" in path else "?"
                url = f"{base}{path}{sep}callback={callback}"
                try:
                    verify_tls = _should_verify_tls(url)
                    r = session.get(url, timeout=timeout_sec, allow_redirects=True, verify=verify_tls)
                except requests.RequestException:
                    continue
                text = _decode_text(r)
                data = _parse_jsonp(text)
                if not isinstance(data, dict):
                    continue
                for key in ("wlan_user_ip", "v4ip", "v46ip", "ss5", "user_ip", "ip"):
                    val = data.get(key)
                    if isinstance(val, str):
                        ip = _decode_wlan_user_ip(val) or val
                        if _is_candidate_wlan_ip(ip, allow_private):
                            return ip

    if not only_status:
        if fallback_host:
            ip = _local_ipv4_for_host(fallback_host)
            if ip and _is_candidate_wlan_ip(ip, allow_private):
                return ip

        ip = probe_ipconfig_ipv4()
        if ip and _is_candidate_wlan_ip(ip, allow_private):
            return ip

    return None


def build_login_url(
    user_account: str,
    user_password: str,
    wlan_user_ip: str,
    portal_host: str = "10.255.254.11",
    portal_port: int = 801,
    wlan_user_mac: str = "000000000000",
    js_version: str = "3.3.1",
) -> str:
    ts = int(time.time() * 1000)
    params = {
        "c": "Portal",
        "a": "login",
        "callback": f"dr{ts}",
        "login_method": "1",
        "user_account": user_account,
        "user_password": user_password,
        "wlan_user_ip": wlan_user_ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": wlan_user_mac,
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "jsVersion": js_version,
        "_": str(ts),
    }
    return f"http://{portal_host}:{portal_port}/eportal/?" + urlencode(params, safe=":@")


def build_login_url_v4(
    user_account: str,
    user_password: str,
    wlan_user_ip: str,
    login_url: str,
    wlan_user_mac: str = "000000000000",
    js_version: str = "4.1.3",
    extra_params: str = "",
) -> str:
    ts = int(time.time() * 1000)
    params = [
        ("callback", f"dr{ts}"),
        ("login_method", "1"),
        ("user_account", user_account),
        ("user_password", user_password),
        ("wlan_user_ip", wlan_user_ip),
        ("wlan_user_ipv6", ""),
        ("wlan_user_mac", wlan_user_mac),
        ("wlan_ac_ip", ""),
        ("wlan_ac_name", ""),
        ("jsVersion", js_version),
    ]
    if extra_params:
        params.extend(parse_qsl(extra_params, keep_blank_values=True))

    query = urlencode(params, doseq=True)
    if not login_url:
        login_url = "https://10.1.1.1:802/eportal/portal/login"
    parsed = urlparse(login_url)
    if parsed.query:
        query = f"{parsed.query}&{query}" if query else parsed.query
    return urlunparse(parsed._replace(query=query))


def _parse_jsonp(text: str) -> Optional[dict]:
    m = re.search(r"\((\{.*\})\)\s*$", text.strip())
    if not m:
        return None
    try:
        import json

        return json.loads(m.group(1))
    except Exception:
        return None


def try_decode_base64(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return None
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=False)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def login_once(
    session: requests.Session,
    url: str,
    timeout_sec: float = 8.0,
    referer: Optional[str] = None,
) -> LoginResult:
    try:
        headers = {"Referer": referer or "http://10.255.254.11/"}
        verify_tls = _should_verify_tls(url)
        r = session.get(url, timeout=timeout_sec, allow_redirects=True, headers=headers, verify=verify_tls)
        text = _decode_text(r)
    except requests.RequestException as e:
        return LoginResult(ok=False, raw=str(e))

    data = _parse_jsonp(text)
    if not data:
        # Fallback: some portals return slightly malformed JSONP.
        m_res = re.search(r'"result"\s*:\s*("?)(\d+)\1', text)
        m_code = re.search(r'"ret_code"\s*:\s*("?)(-?\d+)\1', text)
        m_msg = re.search(r'"msg"\s*:\s*"([^"]*)"', text)
        result = m_res.group(2) if m_res else None
        ret_code = int(m_code.group(2)) if m_code else None
        msg = m_msg.group(1) if m_msg else None
        ok = result == "1"
        return LoginResult(
            ok=ok,
            result=result,
            ret_code=ret_code,
            msg=msg,
            msg_decoded=try_decode_base64(msg),
            raw=text[:500],
        )

    msg = data.get("msg")
    decoded = try_decode_base64(msg)
    ret_code = data.get("ret_code")
    try:
        ret_code_i = int(ret_code) if ret_code is not None else None
    except Exception:
        ret_code_i = None

    ok = str(data.get("result")) == "1"
    return LoginResult(
        ok=ok,
        result=str(data.get("result")) if data.get("result") is not None else None,
        ret_code=ret_code_i,
        msg=str(msg) if msg is not None else None,
        msg_decoded=decoded,
        raw=text,
    )


def _host_in_portal(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    portal_hosts = {"portal.csu.edu.cn", "10.1.1.1", "10.255.254.11"}
    return host in portal_hosts


def test_internet(session: requests.Session, timeout_sec: float = 3.0) -> bool:
    probes = [
        ("http://neverssl.com/", None),
        ("http://www.baidu.com", None),
        ("http://www.qq.com", None),
        ("http://www.bing.com", None),
        ("http://www.msftconnecttest.com/connecttest.txt", b"Microsoft Connect Test"),
    ]
    portal_markers = (
        "eportal",
        "portal.csu.edu.cn",
        "drcom",
        "校园网",
        "上网认证",
        "认证",
        "登录",
    )
    for url, expect in probes:
        try:
            r = session.get(url, timeout=timeout_sec, allow_redirects=True)
        except requests.RequestException:
            continue
        if _host_in_portal(r.url):
            continue
        if r.status_code == 204:
            return True
        if r.status_code == 200:
            # Captive portals may return 200 with a login page body.
            if (r.headers.get("Content-Type", "").lower().startswith("text/html")) or expect is None:
                text = _decode_text(r)[:2000].lower()
                if any(m in text for m in portal_markers):
                    continue
            if expect is None:
                return True
            if expect in (r.content or b""):
                return True
    return False


def redact_login_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        items = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() == "user_password":
                items.append((k, "***"))
            else:
                items.append((k, v))
        query = urlencode(items, doseq=True)
        return urlunparse(parsed._replace(query=query))
    except Exception:
        return url


def normalize_user_account(account: str, portal_type: str) -> str:
    acc = (account or "").strip()
    if not acc:
        return acc
    # If user already provided ISP suffix or prefix, keep it.
    if "@" in acc or acc.startswith(","):
        return acc
    if portal_type == "telecom":
        return f",0,{acc}@telecomn"
    if portal_type == "unicom":
        return f",0,{acc}@unicomn"
    if portal_type == "mobile":
        return f",0,{acc}@cmccn"
    if portal_type == "campus":
        return f",0,{acc}"
    return acc

