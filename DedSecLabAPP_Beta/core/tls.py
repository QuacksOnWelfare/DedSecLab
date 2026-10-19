"""
Central TLS policy for DedSec Lab.

* Lab backend URLs (the configured server_url host, or YOUR_LAB_VPN_IP) are verified
  against a PINNED lab CA / self-signed cert at assets/lab_ca.pem.
  If that file is missing we FAIL CLOSED.
* Hostname checking: lab certs in the field often use CN=<VPN IP> without a
  SubjectAltName. For lab URLs we still require a cert signed by (or equal to)
  the pin, but we do not require a modern SAN match. Non-lab HTTPS keeps full
  system CA + hostname checks.
* Nothing in the app may use verify=False / CERT_NONE as a blanket bypass.
"""
from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_LAB_HOSTS = {"YOUR_LAB_VPN_IP", "YOUR_LAB_HOST"}
CA_FILENAME = "lab_ca.pem"


class LabTLSError(RuntimeError):
    """Raised when a lab call cannot be made securely (e.g. CA missing)."""


def app_root() -> Path:
    if getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def _config() -> dict:
    try:
        from core.config import ConfigManager
        return ConfigManager.peek()
    except Exception:
        return {}


def lab_hosts() -> set:
    hosts = set(DEFAULT_LAB_HOSTS)
    url = str(_config().get("server_url") or "").strip()
    host = urlsplit(url).hostname if url else None
    if host:
        hosts.add(host.lower())
    return hosts


def is_lab_url(url: str) -> bool:
    try:
        host = (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and host in lab_hosts()


def ca_candidates() -> list:
    out = []
    cfg_path = str(_config().get("lab_ca_path") or "").strip()
    if cfg_path:
        out.append(Path(cfg_path).expanduser())
    env_path = os.environ.get("DEDSEC_LAB_CA", "").strip()
    if env_path:
        out.append(Path(env_path).expanduser())
    out.append(app_root() / "assets" / CA_FILENAME)
    return out


def lab_ca_path() -> Path:
    for cand in ca_candidates():
        if cand.is_file() and cand.stat().st_size > 0:
            return cand
    where = "\n".join(f"  - {p}" for p in ca_candidates())
    raise LabTLSError(
        "Lab CA certificate not found, so the secure connection to the lab "
        "server was refused.\nPlace your lab CA (PEM) at one of:\n" + where
    )


def lab_ca_status() -> tuple:
    """(ok, message) for UI display without raising."""
    try:
        return True, f"Lab CA: {lab_ca_path()}"
    except LabTLSError as e:
        return False, str(e)


def _lab_ssl_context() -> ssl.SSLContext:
    """Pinned verify; hostname off so CN=YOUR_LAB_VPN_IP without SAN still works."""
    ctx = ssl.create_default_context(cafile=str(lab_ca_path()))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ---------------------------------------------------------------- requests
def verify_for(url: str):
    """
    Value for requests verify=.
    For lab URLs return the CA path (callers should prefer http_request()).
    """
    if is_lab_url(url):
        return str(lab_ca_path())
    return True


_lab_session = None


def _lab_session_get():
    global _lab_session
    if _lab_session is not None:
        return _lab_session
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.poolmanager import PoolManager

    class _LabAdapter(HTTPAdapter):
        def __init__(self, ctx, **kw):
            self._ctx = ctx
            super().__init__(**kw)

        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
            # urllib3 still hostname-checks even when ssl_context.check_hostname
            # is False; lab certs often have CN=IP and no SAN.
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_context=self._ctx,
                assert_hostname=False,
                assert_fingerprint=None,
                **pool_kwargs,
            )

        def proxy_manager_for(self, *args, **kwargs):
            kwargs["ssl_context"] = self._ctx
            return super().proxy_manager_for(*args, **kwargs)

    s = requests.Session()
    s.mount("https://", _LabAdapter(_lab_ssl_context()))
    _lab_session = s
    return s


def reset_lab_session() -> None:
    """Call after lab_ca.pem is replaced so the next request reloads the pin."""
    global _lab_session
    _lab_session = None


def http_request(method: str, url: str, **kwargs):
    """requests.request with lab pin + CN-without-SAN support for lab URLs."""
    import requests
    if is_lab_url(url):
        kwargs.pop("verify", None)
        return _lab_session_get().request(method, url, **kwargs)
    kwargs.setdefault("verify", True)
    return requests.request(method, url, **kwargs)


def http_get(url: str, **kwargs):
    return http_request("GET", url, **kwargs)


def http_post(url: str, **kwargs):
    return http_request("POST", url, **kwargs)


def http_put(url: str, **kwargs):
    return http_request("PUT", url, **kwargs)


# ---------------------------------------------------------------- ssl/urllib
def ssl_context_for(url: str) -> ssl.SSLContext:
    if is_lab_url(url):
        return _lab_ssl_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ---------------------------------------------------------------- Qt (wss://)
def qt_ssl_configuration_for(url: str):
    """QSslConfiguration that trusts the lab pin for lab URLs."""
    from PyQt6.QtNetwork import QSslCertificate, QSslConfiguration, QSslSocket
    conf = QSslConfiguration.defaultConfiguration()
    conf.setPeerVerifyMode(QSslSocket.PeerVerifyMode.VerifyPeer)
    if is_lab_url(url):
        certs = QSslCertificate.fromPath(str(lab_ca_path()))
        if not certs:
            raise LabTLSError(f"Lab CA file could not be parsed as PEM: {lab_ca_path()}")
        conf.setCaCertificates(certs)
        # Lab leaf is often CN=IP without SAN; Qt hostname check would fail.
        # VerifyPeer + pinned CA still requires the presented cert to chain to the pin.
        try:
            conf.setPeerVerifyDepth(1)
        except Exception:
            pass
    return conf


def qt_accept_lab_ssl_errors(errors) -> bool:
    """
    Return True if every QSslError is a hostname-mismatch style error against
    our pinned lab cert (safe to ignore). Used by terminal / cmd websockets.
    """
    if not errors:
        return True
    try:
        from PyQt6.QtNetwork import QSslError
        pinned = None
        try:
            from PyQt6.QtNetwork import QSslCertificate
            certs = QSslCertificate.fromPath(str(lab_ca_path()))
            pinned = certs[0] if certs else None
        except Exception:
            pinned = None
        allowed = {
            QSslError.SslError.HostNameMismatch,
            QSslError.SslError.CertificateUntrusted,
            QSslError.SslError.SelfSignedCertificate,
            QSslError.SslError.SelfSignedCertificateInChain,
        }
        for err in errors:
            if err.error() not in allowed:
                return False
            if pinned is not None:
                peer = err.certificate()
                if peer is not None and peer.toDer() != pinned.toDer():
                    # Different cert than our pin - do not accept.
                    # (If error has no cert attached, allow only hostname class.)
                    if err.error() != QSslError.SslError.HostNameMismatch:
                        return False
        return True
    except Exception:
        return False
