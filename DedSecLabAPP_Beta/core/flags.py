"""Country flag helpers for the DedSec VPN gate.

Flags: assets/flags/<cc>.png (lowercase ISO 3166-1 alpha-2, from flagcdn.com).
Geo lookup: free no-key ip-api.com country endpoint (no API key is used).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import urllib.request
from pathlib import Path

COUNTRY_NAMES: dict[str, str] = {
    'ad': 'Andorra',
    'ae': 'United Arab Emirates',
    'af': 'Afghanistan',
    'ag': 'Antigua and Barbuda',
    'ai': 'Anguilla',
    'al': 'Albania',
    'am': 'Armenia',
    'ao': 'Angola',
    'aq': 'Antarctica',
    'ar': 'Argentina',
    'as': 'American Samoa',
    'at': 'Austria',
    'au': 'Australia',
    'aw': 'Aruba',
    'ax': 'Åland Islands',
    'az': 'Azerbaijan',
    'ba': 'Bosnia and Herzegovina',
    'bb': 'Barbados',
    'bd': 'Bangladesh',
    'be': 'Belgium',
    'bf': 'Burkina Faso',
    'bg': 'Bulgaria',
    'bh': 'Bahrain',
    'bi': 'Burundi',
    'bj': 'Benin',
    'bl': 'Saint Barthélemy',
    'bm': 'Bermuda',
    'bn': 'Brunei',
    'bo': 'Bolivia',
    'bq': 'Caribbean Netherlands',
    'br': 'Brazil',
    'bs': 'Bahamas',
    'bt': 'Bhutan',
    'bv': 'Bouvet Island',
    'bw': 'Botswana',
    'by': 'Belarus',
    'bz': 'Belize',
    'ca': 'Canada',
    'cc': 'Cocos (Keeling) Islands',
    'cd': 'DR Congo',
    'cf': 'Central African Republic',
    'cg': 'Republic of the Congo',
    'ch': 'Switzerland',
    'ci': "Côte d'Ivoire (Ivory Coast)",
    'ck': 'Cook Islands',
    'cl': 'Chile',
    'cm': 'Cameroon',
    'cn': 'China',
    'co': 'Colombia',
    'cr': 'Costa Rica',
    'cu': 'Cuba',
    'cv': 'Cape Verde',
    'cw': 'Curaçao',
    'cx': 'Christmas Island',
    'cy': 'Cyprus',
    'cz': 'Czechia',
    'de': 'Germany',
    'dj': 'Djibouti',
    'dk': 'Denmark',
    'dm': 'Dominica',
    'do': 'Dominican Republic',
    'dz': 'Algeria',
    'ec': 'Ecuador',
    'ee': 'Estonia',
    'eg': 'Egypt',
    'eh': 'Western Sahara',
    'er': 'Eritrea',
    'es': 'Spain',
    'et': 'Ethiopia',
    'eu': 'European Union',
    'fi': 'Finland',
    'fj': 'Fiji',
    'fk': 'Falkland Islands',
    'fm': 'Micronesia',
    'fo': 'Faroe Islands',
    'fr': 'France',
    'ga': 'Gabon',
    'gb': 'United Kingdom',
    'gd': 'Grenada',
    'ge': 'Georgia',
    'gf': 'French Guiana',
    'gg': 'Guernsey',
    'gh': 'Ghana',
    'gi': 'Gibraltar',
    'gl': 'Greenland',
    'gm': 'Gambia',
    'gn': 'Guinea',
    'gp': 'Guadeloupe',
    'gq': 'Equatorial Guinea',
    'gr': 'Greece',
    'gs': 'South Georgia',
    'gt': 'Guatemala',
    'gu': 'Guam',
    'gw': 'Guinea-Bissau',
    'gy': 'Guyana',
    'hk': 'Hong Kong',
    'hm': 'Heard Island and McDonald Islands',
    'hn': 'Honduras',
    'hr': 'Croatia',
    'ht': 'Haiti',
    'hu': 'Hungary',
    'id': 'Indonesia',
    'ie': 'Ireland',
    'il': 'Israel',
    'im': 'Isle of Man',
    'in': 'India',
    'io': 'British Indian Ocean Territory',
    'iq': 'Iraq',
    'ir': 'Iran',
    'is': 'Iceland',
    'it': 'Italy',
    'je': 'Jersey',
    'jm': 'Jamaica',
    'jo': 'Jordan',
    'jp': 'Japan',
    'ke': 'Kenya',
    'kg': 'Kyrgyzstan',
    'kh': 'Cambodia',
    'ki': 'Kiribati',
    'km': 'Comoros',
    'kn': 'Saint Kitts and Nevis',
    'kp': 'North Korea',
    'kr': 'South Korea',
    'kw': 'Kuwait',
    'ky': 'Cayman Islands',
    'kz': 'Kazakhstan',
    'la': 'Laos',
    'lb': 'Lebanon',
    'lc': 'Saint Lucia',
    'li': 'Liechtenstein',
    'lk': 'Sri Lanka',
    'lr': 'Liberia',
    'ls': 'Lesotho',
    'lt': 'Lithuania',
    'lu': 'Luxembourg',
    'lv': 'Latvia',
    'ly': 'Libya',
    'ma': 'Morocco',
    'mc': 'Monaco',
    'md': 'Moldova',
    'me': 'Montenegro',
    'mf': 'Saint Martin',
    'mg': 'Madagascar',
    'mh': 'Marshall Islands',
    'mk': 'North Macedonia',
    'ml': 'Mali',
    'mm': 'Myanmar',
    'mn': 'Mongolia',
    'mo': 'Macau',
    'mp': 'Northern Mariana Islands',
    'mq': 'Martinique',
    'mr': 'Mauritania',
    'ms': 'Montserrat',
    'mt': 'Malta',
    'mu': 'Mauritius',
    'mv': 'Maldives',
    'mw': 'Malawi',
    'mx': 'Mexico',
    'my': 'Malaysia',
    'mz': 'Mozambique',
    'na': 'Namibia',
    'nc': 'New Caledonia',
    'ne': 'Niger',
    'nf': 'Norfolk Island',
    'ng': 'Nigeria',
    'ni': 'Nicaragua',
    'nl': 'Netherlands',
    'no': 'Norway',
    'np': 'Nepal',
    'nr': 'Nauru',
    'nu': 'Niue',
    'nz': 'New Zealand',
    'om': 'Oman',
    'pa': 'Panama',
    'pe': 'Peru',
    'pf': 'French Polynesia',
    'pg': 'Papua New Guinea',
    'ph': 'Philippines',
    'pk': 'Pakistan',
    'pl': 'Poland',
    'pm': 'Saint Pierre and Miquelon',
    'pn': 'Pitcairn Islands',
    'pr': 'Puerto Rico',
    'ps': 'Palestine',
    'pt': 'Portugal',
    'pw': 'Palau',
    'py': 'Paraguay',
    'qa': 'Qatar',
    're': 'Réunion',
    'ro': 'Romania',
    'rs': 'Serbia',
    'ru': 'Russia',
    'rw': 'Rwanda',
    'sa': 'Saudi Arabia',
    'sb': 'Solomon Islands',
    'sc': 'Seychelles',
    'sd': 'Sudan',
    'se': 'Sweden',
    'sg': 'Singapore',
    'sh': 'Saint Helena, Ascension and Tristan da Cunha',
    'si': 'Slovenia',
    'sj': 'Svalbard and Jan Mayen',
    'sk': 'Slovakia',
    'sl': 'Sierra Leone',
    'sm': 'San Marino',
    'sn': 'Senegal',
    'so': 'Somalia',
    'sr': 'Suriname',
    'ss': 'South Sudan',
    'st': 'São Tomé and Príncipe',
    'sv': 'El Salvador',
    'sx': 'Sint Maarten',
    'sy': 'Syria',
    'sz': 'Eswatini (Swaziland)',
    'tc': 'Turks and Caicos Islands',
    'td': 'Chad',
    'tf': 'French Southern and Antarctic Lands',
    'tg': 'Togo',
    'th': 'Thailand',
    'tj': 'Tajikistan',
    'tk': 'Tokelau',
    'tl': 'Timor-Leste',
    'tm': 'Turkmenistan',
    'tn': 'Tunisia',
    'to': 'Tonga',
    'tr': 'Turkey',
    'tt': 'Trinidad and Tobago',
    'tv': 'Tuvalu',
    'tw': 'Taiwan',
    'tz': 'Tanzania',
    'ua': 'Ukraine',
    'ug': 'Uganda',
    'um': 'United States Minor Outlying Islands',
    'un': 'United Nations',
    'us': 'United States',
    'uy': 'Uruguay',
    'uz': 'Uzbekistan',
    'va': 'Vatican City (Holy See)',
    'vc': 'Saint Vincent and the Grenadines',
    've': 'Venezuela',
    'vg': 'British Virgin Islands',
    'vi': 'United States Virgin Islands',
    'vn': 'Vietnam',
    'vu': 'Vanuatu',
    'wf': 'Wallis and Futuna',
    'ws': 'Samoa',
    'xk': 'Kosovo',
    'ye': 'Yemen',
    'yt': 'Mayotte',
    'za': 'South Africa',
    'zm': 'Zambia',
    'zw': 'Zimbabwe',
}

# Common aliases -> code (for name_to_code).
_ALIASES = {
    "uk": "gb", "great britain": "gb", "britain": "gb", "england": "gb",
    "united kingdom": "gb", "usa": "us", "united states of america": "us",
    "america": "us", "eu": "fr", "holland": "nl", "south korea": "kr",
    "korea": "kr", "russia": "ru", "czech republic": "cz",
}

# Built-in gate slot ids -> default country code.
SLOT_CODES = {"eu": "fr", "canada": "ca", "usa": "us", "uk": "gb"}


def _flag_dirs() -> list[Path]:
    here = Path(__file__).resolve()
    roots = []
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots += [here.parents[1], Path.cwd()]
    return [r / "assets" / "flags" for r in roots]


def code_to_name(code: str | None) -> str:
    if not code:
        return "Unknown"
    return COUNTRY_NAMES.get(code.lower(), code.upper())


def name_to_code(name: str | None) -> str | None:
    if not name:
        return None
    key = name.strip().lower()
    if key in _ALIASES:
        return _ALIASES[key]
    if len(key) == 2 and key in COUNTRY_NAMES:
        return key
    for cc, nm in COUNTRY_NAMES.items():
        if nm.lower() == key:
            return cc
    for cc, nm in COUNTRY_NAMES.items():
        if key in nm.lower():
            return cc
    return None


def unknown_flag_path() -> Path | None:
    for d in _flag_dirs():
        p = d / "unknown.png"
        if p.is_file():
            return p
    return None


def flag_path(code: str | None) -> Path | None:
    """assets/flags/<cc>.png, or unknown.png, or None."""
    if code:
        cc = code.strip().lower()
        cc = _ALIASES.get(cc, cc)
        for d in _flag_dirs():
            p = d / f"{cc}.png"
            if p.is_file():
                return p
    return unknown_flag_path()


# ---------------------------------------------------------------- detection

def parse_ovpn_remote(path: str) -> tuple[str, int, str] | None:
    """First `remote <host> [port] [proto]` in an .ovpn -> (host, port, proto)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    port_default, proto_default = 1194, "udp"
    host = None
    port = None
    proto = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        parts = line.split()
        kw = parts[0].lower()
        if kw == "port" and len(parts) > 1 and parts[1].isdigit():
            port_default = int(parts[1])
        elif kw == "proto" and len(parts) > 1:
            proto_default = parts[1].lower()
        elif kw == "remote" and len(parts) > 1 and host is None:
            host = parts[1]
            if len(parts) > 2 and parts[2].isdigit():
                port = int(parts[2])
            if len(parts) > 3:
                proto = parts[3].lower()
    if not host:
        return None
    return host, port or port_default, (proto or proto_default)


def resolve_host(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def geolocate_ip(ip: str, timeout: float = 4.0) -> dict | None:
    """Free no-key endpoint. Returns {country, countryCode, city} or None."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DedSecLab/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception:
        return None
    if data.get("status") != "success" or not data.get("countryCode"):
        return None
    return data


def detect_ovpn_country(path: str, timeout: float = 4.0) -> dict:
    """Blocking: parse -> resolve -> geolocate. Always returns a dict."""
    out = {"ok": False, "host": "", "ip": "", "port": 1194, "proto": "udp",
           "cc": "", "country": "", "city": "", "error": ""}
    rem = parse_ovpn_remote(path)
    if not rem:
        out["error"] = "No 'remote' line in config"
        return out
    out["host"], out["port"], out["proto"] = rem
    ip = resolve_host(rem[0])
    if not ip:
        out["error"] = f"Could not resolve {rem[0]}"
        return out
    out["ip"] = ip
    geo = geolocate_ip(ip, timeout=timeout)
    if not geo:
        out["error"] = "Country lookup failed"
        return out
    out["cc"] = str(geo.get("countryCode", "")).lower()
    out["country"] = geo.get("country") or code_to_name(out["cc"])
    out["city"] = geo.get("city") or ""
    out["ok"] = True
    return out
