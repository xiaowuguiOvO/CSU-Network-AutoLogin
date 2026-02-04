from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import requests


_IP_RE = r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"


@dataclass
class LoginResult:
    ok: bool
    result: Optional[str] = None
    ret_code: Optional[int] = None
    msg: Optional[str] = None
    msg_decoded: Optional[str] = None
    raw: str = ""


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


def probe_wlan_user_ip(session: requests.Session, probe_url: str, timeout_sec: float = 3.0) -> Optional[str]:
    """
    Return wlan_user_ip (external ip) by parsing portal HTML.
    """
    urls = [probe_url, "http://10.255.254.11/", "http://10.255.254.11:801/", "http://10.255.254.11:801/eportal/"]
    seen: set[str] = set()
    for url in urls:
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=timeout_sec, allow_redirects=True)
        except requests.RequestException:
            continue

        # Redirect URL may contain wlan_user_ip.
        if "wlan_user_ip=" in r.url:
            m = re.search(r"wlan_user_ip=([^&]+)", r.url)
            if m:
                return m.group(1)

        text = _decode_text(r)

        # Dr.COM pages often expose lip/v4ip variables.
        for pat in (
            rf"lip\s*=\s*'{_IP_RE}'",
            rf"v4ip\s*=\s*'{_IP_RE}'",
            rf"wlan_user_ip\s*=\s*{_IP_RE}",
            rf"wlan_user_ip=({_IP_RE})",
        ):
            mm = re.search(pat, text, re.I)
            if mm:
                # last group is ip
                return mm.group(mm.lastindex or 1)

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


def login_once(session: requests.Session, url: str, timeout_sec: float = 8.0) -> LoginResult:
    try:
        r = session.get(url, timeout=timeout_sec, allow_redirects=True, headers={"Referer": "http://10.255.254.11/"})
        text = _decode_text(r)
    except requests.RequestException as e:
        return LoginResult(ok=False, raw=str(e))

    data = _parse_jsonp(text)
    if not data:
        return LoginResult(ok=False, raw=text[:500])

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


def test_internet(session: requests.Session, timeout_sec: float = 3.0) -> bool:
    try:
        r = session.get("http://www.msftconnecttest.com/connecttest.txt", timeout=timeout_sec, allow_redirects=False)
        if r.status_code != 200:
            return False
        return b"Microsoft Connect Test" in (r.content or b"")
    except requests.RequestException:
        return False

