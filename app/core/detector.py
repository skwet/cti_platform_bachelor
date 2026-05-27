import re
import ipaddress
from app.models.ioc import IoCType

MD5 = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1 = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256 = re.compile(r'^[a-fA-F0-9]{64}$')
EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
URL = re.compile(r'^https?://', re.IGNORECASE)
DOMAIN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def detect_type(value: str) -> IoCType | None:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return IoCType.IP
    except ValueError:
        pass
    if MD5.match(v): return IoCType.HASH_MD5
    if SHA1.match(v): return IoCType.HASH_SHA1
    if SHA256.match(v): return IoCType.HASH_SHA256
    if EMAIL.match(v): return IoCType.EMAIL
    if URL.match(v): return IoCType.URL
    if DOMAIN.match(v): return IoCType.DOMAIN
    return None

def normalize(value: str) -> str:
    return value.strip().lower()
