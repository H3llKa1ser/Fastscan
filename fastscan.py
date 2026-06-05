#!/usr/bin/env python3
"""
FastScan - A fast, accurate Nikto-style web server vulnerability scanner.

Imitates Nikto's workflow and output style while using async I/O for speed and
smarter response analysis for accuracy. Adds:
  * TLS / certificate / cipher inspection
  * CMS & technology fingerprinting (WordPress, Joomla, Drupal, etc.)
  * Plugin architecture for custom checks
  * Nikto-style banner, tuning options, and report formats (txt/json/csv/html)

LEGAL: Only use against systems you own or are explicitly authorized to test.
Unauthorized scanning may be illegal in your jurisdiction.
"""

import asyncio
import argparse
import csv
import hashlib
import io
import json
import re
import socket
import ssl
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    sys.exit("Please install aiohttp:  pip install aiohttp")


VERSION = "2.0"
BANNER = r"""
- FastScan v{ver} ----------------------------------------------------------
+ A faster, Nikto-style async web scanner.  Authorized testing ONLY.
----------------------------------------------------------------------------
""".format(ver=VERSION)


# ============================================================================
#  Nikto-style "tuning" categories (mirrors nikto -Tuning)
# ============================================================================
TUNING = {
    "1": "Interesting File / Seen in logs",
    "2": "Misconfiguration / Default File",
    "3": "Information Disclosure",
    "4": "Injection (XSS/Script/HTML)",
    "5": "Remote File Retrieval - Inside Web Root",
    "6": "Denial of Service",
    "7": "Remote File Retrieval - Server Wide",
    "8": "Command Execution / Remote Shell",
    "9": "SQL Injection",
    "a": "Authentication Bypass",
    "b": "Software Identification",
    "c": "Remote Source Inclusion",
    "d": "WebService",
    "e": "Administrative Console",
    "x": "Reverse Tuning (run everything except the above)",
}


# ============================================================================
#  Data structures
# ============================================================================
@dataclass
class Finding:
    severity: str           # info, low, medium, high, critical
    osvdb: str              # Nikto-style OSVDB / ID reference (or "0")
    title: str
    url: str
    evidence: str = ""
    method: str = "GET"
    tuning: str = "3"

    def to_dict(self):
        return {
            "severity": self.severity,
            "id": self.osvdb,
            "title": self.title,
            "url": self.url,
            "evidence": self.evidence,
            "method": self.method,
            "tuning": self.tuning,
        }


@dataclass
class ScanConfig:
    target: str
    port: int = 0
    ssl_force: bool = False
    concurrency: int = 50
    timeout: float = 10.0
    user_agent: str = "Mozilla/5.0 (FastScan/%s; +authorized-testing)" % VERSION
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 3
    cookies: str = ""
    headers: dict = field(default_factory=dict)
    auth: str = ""             # user:pass for basic auth
    output: str = ""
    output_format: str = "text"   # text | json | csv | html
    wordlist: str = ""
    rate_limit: float = 0.0
    tuning: str = ""           # restrict checks to these tuning categories
    no_tls_scan: bool = False
    no_cms_scan: bool = False
    plugins_enabled: bool = True


# ============================================================================
#  Signature databases (Nikto-style db_tests, expanded)
# ============================================================================
# (path, osvdb_id, description, severity, tuning_category)
DEFAULT_PATHS = [
    # --- Administrative consoles (tuning e) ---
    ("/admin/", "3092", "Admin login/interface found", "medium", "e"),
    ("/admin/login", "0", "Admin login page", "low", "e"),
    ("/administrator/", "0", "Joomla administrator interface", "medium", "e"),
    ("/wp-admin/", "0", "WordPress admin directory", "low", "e"),
    ("/wp-login.php", "0", "WordPress login page", "low", "e"),
    ("/login.php", "0", "Generic login page", "info", "e"),
    ("/manager/html", "0", "Tomcat Manager interface", "high", "e"),
    ("/manager/status", "0", "Tomcat status page", "medium", "e"),
    ("/host-manager/html", "0", "Tomcat host-manager", "high", "e"),
    ("/phpmyadmin/", "3092", "phpMyAdmin interface found", "high", "e"),
    ("/pma/", "3092", "phpMyAdmin (alternate path)", "high", "e"),
    ("/dbadmin/", "0", "Database admin interface", "high", "e"),
    ("/adminer.php", "0", "Adminer database tool", "high", "e"),
    ("/jenkins/", "0", "Jenkins CI server", "medium", "e"),
    ("/jmx-console/", "0", "JBoss JMX console (often unauthenticated)", "high", "e"),
    ("/web-console/", "0", "JBoss web-console", "high", "e"),
    ("/console/", "0", "Management console", "medium", "e"),
    ("/manager/", "0", "Management interface", "medium", "e"),

    # --- Misconfiguration / default files (tuning 2) ---
    ("/server-status", "0", "Apache mod_status exposed", "medium", "2"),
    ("/server-info", "0", "Apache mod_info exposed", "medium", "3"),
    ("/.well-known/security.txt", "0", "security.txt present", "info", "3"),
    ("/crossdomain.xml", "0", "Flash crossdomain.xml policy", "low", "2"),
    ("/clientaccesspolicy.xml", "0", "Silverlight access policy", "low", "2"),
    ("/test.php", "0", "Test script present", "low", "2"),
    ("/example.html", "0", "Default example file", "info", "2"),
    ("/icons/README", "3233", "Apache default icons README", "info", "2"),

    # --- Information disclosure (tuning 3) ---
    ("/phpinfo.php", "0", "phpinfo() output exposed", "medium", "3"),
    ("/info.php", "0", "phpinfo() output exposed", "medium", "3"),
    ("/robots.txt", "0", "robots.txt file", "info", "3"),
    ("/sitemap.xml", "0", "sitemap.xml file", "info", "3"),
    ("/.DS_Store", "0", "macOS .DS_Store directory listing leak", "low", "3"),
    ("/swagger-ui.html", "0", "Swagger UI exposed", "low", "3"),
    ("/swagger/index.html", "0", "Swagger UI exposed", "low", "3"),
    ("/api/swagger.json", "0", "Swagger/OpenAPI spec exposed", "low", "3"),
    ("/openapi.json", "0", "OpenAPI spec exposed", "low", "3"),
    ("/graphql", "0", "GraphQL endpoint", "low", "d"),
    ("/actuator", "0", "Spring Boot Actuator base", "medium", "3"),
    ("/actuator/env", "0", "Spring Actuator env (may leak secrets)", "high", "3"),
    ("/actuator/health", "0", "Spring Actuator health", "low", "3"),
    ("/actuator/mappings", "0", "Spring Actuator mappings", "medium", "3"),
    ("/actuator/heapdump", "0", "Spring Actuator heapdump (memory leak)", "critical", "3"),
    ("/v2/_catalog", "0", "Docker registry catalog exposed", "high", "3"),
    ("/_cat/indices", "0", "Elasticsearch indices exposed", "high", "3"),

    # --- Interesting/sensitive files (tuning 1 & 5) ---
    ("/.env", "0", "Environment file may contain secrets", "critical", "5"),
    ("/.env.local", "0", "Local environment file", "critical", "5"),
    ("/.env.production", "0", "Production environment file", "critical", "5"),
    ("/.git/config", "0", "Exposed .git repository config", "high", "5"),
    ("/.git/HEAD", "0", "Exposed .git repository HEAD", "high", "5"),
    ("/.git/index", "0", "Exposed .git index", "high", "5"),
    ("/.svn/entries", "0", "Exposed Subversion .svn entries", "high", "5"),
    ("/.svn/wc.db", "0", "Exposed SVN working copy DB", "high", "5"),
    ("/.hg/store/00manifest.i", "0", "Exposed Mercurial repository", "high", "5"),
    ("/.bzr/branch/branch.conf", "0", "Exposed Bazaar repository", "high", "5"),
    ("/.htaccess", "0", ".htaccess file accessible", "medium", "5"),
    ("/.htpasswd", "0", ".htpasswd file accessible", "high", "5"),
    ("/web.config", "0", "IIS web.config accessible", "medium", "5"),
    ("/config.php", "0", "PHP configuration file", "medium", "5"),
    ("/config.php.bak", "0", "PHP config backup file", "high", "5"),
    ("/config.php.old", "0", "PHP config old file", "high", "5"),
    ("/config.php~", "0", "PHP config editor backup", "high", "5"),
    ("/wp-config.php.bak", "0", "WordPress config backup (DB creds)", "critical", "5"),
    ("/wp-config.php~", "0", "WordPress config editor backup", "critical", "5"),
    ("/wp-config.php.save", "0", "WordPress config save file", "critical", "5"),
    ("/composer.json", "0", "PHP Composer manifest", "low", "5"),
    ("/composer.lock", "0", "PHP Composer lock (dependency versions)", "low", "5"),
    ("/package.json", "0", "Node.js package manifest", "low", "5"),
    ("/package-lock.json", "0", "npm lock file", "low", "5"),
    ("/yarn.lock", "0", "Yarn lock file", "low", "5"),
    ("/Gemfile", "0", "Ruby Gemfile", "low", "5"),
    ("/Gemfile.lock", "0", "Ruby Gemfile lock", "low", "5"),
    ("/requirements.txt", "0", "Python requirements file", "low", "5"),
    ("/Dockerfile", "0", "Dockerfile exposed", "low", "5"),
    ("/docker-compose.yml", "0", "Docker compose file (may leak config)", "medium", "5"),
    ("/Makefile", "0", "Makefile exposed", "low", "5"),

    # --- Backups / archives (tuning 1) ---
    ("/backup.zip", "0", "Backup archive present", "high", "1"),
    ("/backup.tar.gz", "0", "Backup tarball present", "high", "1"),
    ("/backup.sql", "0", "SQL backup dump present", "high", "1"),
    ("/dump.sql", "0", "SQL dump present", "high", "1"),
    ("/database.sql", "0", "SQL database dump present", "high", "1"),
    ("/db.sql", "0", "SQL dump present", "high", "1"),
    ("/site.zip", "0", "Site archive present", "high", "1"),
    ("/www.zip", "0", "Web root archive present", "high", "1"),
    ("/backup/", "0", "Backup directory present", "medium", "1"),
    ("/old/", "0", "Old files directory", "low", "1"),
    ("/temp/", "0", "Temp directory", "low", "1"),
    ("/tmp/", "0", "Temp directory", "low", "1"),

    # --- Credentials / keys (tuning 5/7) ---
    ("/id_rsa", "0", "Private SSH key exposed", "critical", "7"),
    ("/.ssh/id_rsa", "0", "Private SSH key exposed", "critical", "7"),
    ("/.ssh/authorized_keys", "0", "SSH authorized_keys exposed", "high", "7"),
    ("/.aws/credentials", "0", "AWS credentials file exposed", "critical", "7"),
    ("/.npmrc", "0", "npm config (may contain tokens)", "high", "5"),
    ("/.dockercfg", "0", "Docker config (registry creds)", "high", "5"),
    ("/.netrc", "0", "netrc credentials file", "high", "5"),

    # --- CGI / shells (tuning 8) ---
    ("/cgi-bin/", "0", "CGI directory", "low", "1"),
    ("/cgi-bin/test-cgi", "0", "test-cgi script (info disclosure)", "medium", "3"),
    ("/cgi-bin/printenv", "0", "printenv CGI (env disclosure)", "medium", "3"),
    ("/shell.php", "0", "Possible web shell", "critical", "8"),
    ("/c99.php", "0", "c99 web shell signature", "critical", "8"),
    ("/r57.php", "0", "r57 web shell signature", "critical", "8"),
    ("/cmd.php", "0", "Possible command shell", "critical", "8"),
]

# Header-based security checks
SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "Missing 'Strict-Transport-Security' (HSTS) header"),
    "content-security-policy": ("medium", "Missing 'Content-Security-Policy' header"),
    "x-frame-options": ("low", "Missing 'X-Frame-Options' header (clickjacking risk)"),
    "x-content-type-options": ("low", "Missing 'X-Content-Type-Options: nosniff' header"),
    "referrer-policy": ("info", "Missing 'Referrer-Policy' header"),
    "permissions-policy": ("info", "Missing 'Permissions-Policy' header"),
}

VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                   "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
                   "x-runtime", "x-version", "via"]

# Confirm-content signatures to reduce false positives
INTERESTING_CONTENT = [
    (re.compile(rb"(DB_PASSWORD|DB_PASS|DATABASE_URL|SECRET_KEY)\s*=", re.I), "secret/credential in .env", "critical"),
    (re.compile(rb"AWS_(SECRET|ACCESS)_KEY", re.I), "AWS key reference", "critical"),
    (re.compile(rb"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "private key material", "critical"),
    (re.compile(rb"\[core\][^\]]*repositoryformatversion", re.I), "git config content", "high"),
    (re.compile(rb"ref:\s+refs/heads/"), "git HEAD content", "high"),
    (re.compile(rb"<title>phpinfo\(\)</title>", re.I), "phpinfo() output", "medium"),
    (re.compile(rb"<h1[^>]*>PHP Version", re.I), "phpinfo() version block", "medium"),
    (re.compile(rb"Apache Server Status", re.I), "Apache server-status content", "medium"),
    (re.compile(rb'"_shards"\s*:', re.I), "Elasticsearch JSON response", "high"),
    (re.compile(rb'"repositories"\s*:\s*\[', re.I), "Docker registry catalog JSON", "high"),
    (re.compile(rb"define\s*\(\s*['\"]DB_PASSWORD", re.I), "WordPress DB credentials", "critical"),
]


# CMS / technology fingerprints
CMS_FINGERPRINTS = [
    {
        "name": "WordPress",
        "paths": ["/wp-login.php", "/wp-includes/", "/readme.html", "/wp-json/"],
        "body": [re.compile(rb"/wp-content/", re.I), re.compile(rb'name="generator" content="WordPress', re.I)],
        "header": {"x-powered-by": None},
        "version": re.compile(rb'content="WordPress (\d+\.\d+(?:\.\d+)?)"', re.I),
        "version_path": "/readme.html",
        "version_path_re": re.compile(rb"Version (\d+\.\d+(?:\.\d+)?)"),
    },
    {
        "name": "Joomla",
        "paths": ["/administrator/", "/language/en-GB/en-GB.xml"],
        "body": [re.compile(rb"/components/com_", re.I), re.compile(rb"Joomla", re.I)],
        "version": re.compile(rb"<version>(\d+\.\d+(?:\.\d+)?)</version>", re.I),
        "version_path": "/administrator/manifests/files/joomla.xml",
    },
    {
        "name": "Drupal",
        "paths": ["/CHANGELOG.txt", "/core/CHANGELOG.txt", "/user/login"],
        "body": [re.compile(rb"Drupal", re.I), re.compile(rb"/sites/default/files", re.I)],
        "header": {"x-generator": re.compile(r"Drupal", re.I)},
        "version": re.compile(rb"Drupal (\d+\.\d+(?:\.\d+)?),", re.I),
        "version_path": "/CHANGELOG.txt",
    },
    {
        "name": "Magento",
        "paths": ["/magento_version", "/static/version"],
        "body": [re.compile(rb"Mage\.Cookies", re.I), re.compile(rb"/skin/frontend/", re.I)],
    },
    {
        "name": "phpBB",
        "paths": ["/viewtopic.php", "/styles/"],
        "body": [re.compile(rb"phpBB", re.I)],
    },
]


# ============================================================================
#  Soft-404 detection
# ============================================================================
class SoftNotFound:
    def __init__(self):
        self.statuses = set()
        self.lengths = []
        self.body_hashes = set()
        self.calibrated = False

    async def calibrate(self, scanner):
        probes = [
            "/this_should_not_exist_%d.html" % int(time.time()),
            "/nonexistent_%s" % hashlib.md5(str(time.time()).encode()).hexdigest()[:12],
            "/random_dir_404_test_%d/" % int(time.time() % 9999),
        ]
        for p in probes:
            resp = await scanner.fetch(p)
            if resp is None:
                continue
            self.statuses.add(resp["status"])
            self.lengths.append(resp["length"])
            self.body_hashes.add(resp["body_hash"])
        self.calibrated = True

    def looks_like_404(self, resp):
        if resp["status"] in (404, 410):
            return True
        if resp["status"] in self.statuses:
            if resp["body_hash"] in self.body_hashes:
                return True
            for L in self.lengths:
                if L > 0 and abs(resp["length"] - L) / max(L, 1) < 0.05:
                    return True
        return False


# ============================================================================
#  Plugin architecture
# ============================================================================
class Plugin(ABC):
    """Base class for custom checks. Subclass and implement run()."""
    name = "unnamed"
    tuning = "3"

    @abstractmethod
    async def run(self, scanner: "FastScan"):
        ...


class HttpMethodsPlugin(Plugin):
    name = "http-methods"
    tuning = "2"

    async def run(self, scanner):
        resp = await scanner.fetch("/", method="OPTIONS")
        if resp and "allow" in resp["headers"]:
            allow = resp["headers"]["allow"].upper()
            for risky in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "MOVE", "COPY"):
                if risky in allow:
                    sev = "high" if risky in ("PUT", "DELETE", "MOVE", "COPY") else "medium"
                    await scanner.add(Finding(
                        sev, "0", f"HTTP method '{risky}' is allowed",
                        resp["url"], evidence=f"Allow: {resp['headers']['allow']}",
                        method="OPTIONS", tuning="2",
                    ))
        trace = await scanner.fetch("/", method="TRACE")
        if trace and trace["status"] == 200 and b"TRACE /" in trace["body"]:
            await scanner.add(Finding(
                "medium", "0", "HTTP TRACE method active (Cross-Site Tracing / XST)",
                trace["url"], method="TRACE", tuning="2",
            ))


class XSSReflectionPlugin(Plugin):
    """Lightweight reflected-XSS probe in common query params (tuning 4)."""
    name = "xss-reflection"
    tuning = "4"

    PARAMS = ["q", "search", "s", "query", "id", "name", "page", "keyword"]
    MARKER = "fsx9k3z"
    PAYLOAD = f"<{MARKER}>"

    async def run(self, scanner):
        for param in self.PARAMS:
            path = f"/?{param}={self.PAYLOAD}"
            resp = await scanner.fetch(path)
            if resp is None:
                continue
            # Reflected unescaped => potential XSS
            if self.PAYLOAD.encode() in resp["body"]:
                await scanner.add(Finding(
                    "high", "0",
                    f"Reflected, unescaped input in parameter '{param}' (possible XSS)",
                    resp["url"],
                    evidence=f"Payload '{self.PAYLOAD}' reflected verbatim",
                    tuning="4",
                ))


class SqlErrorPlugin(Plugin):
    """Detect SQL error messages from a quote injection (tuning 9)."""
    name = "sql-error"
    tuning = "9"

    PARAMS = ["id", "page", "cat", "item", "product", "user"]
    SQL_ERRORS = [
        re.compile(rb"SQL syntax.*MySQL", re.I),
        re.compile(rb"Warning.*\bmysqli?_", re.I),
        re.compile(rb"PostgreSQL.*ERROR", re.I),
        re.compile(rb"ORA-\d{5}", re.I),
        re.compile(rb"Microsoft OLE DB Provider for SQL Server", re.I),
        re.compile(rb"Unclosed quotation mark after the character string", re.I),
        re.compile(rb"SQLite/JDBCDriver", re.I),
        re.compile(rb"sqlite3.OperationalError", re.I),
    ]

    async def run(self, scanner):
        for param in self.PARAMS:
            path = f"/?{param}=1'"
            resp = await scanner.fetch(path)
            if resp is None:
                continue
            for pat in self.SQL_ERRORS:
                if pat.search(resp["body"]):
                    await scanner.add(Finding(
                        "high", "0",
                        f"SQL error triggered via parameter '{param}' (possible SQLi)",
                        resp["url"],
                        evidence=f"Matched DB error pattern: {pat.pattern}",
                        tuning="9",
                    ))
                    break


class DirectoryListingPlugin(Plugin):
    """Detect directory listing on common directories (tuning 3)."""
    name = "dir-listing"
    tuning = "3"

    DIRS = ["/images/", "/uploads/", "/files/", "/backup/", "/assets/", "/static/", "/data/"]
    SIGNS = [
        re.compile(rb"<title>Index of /", re.I),
        re.compile(rb"<h1>Index of /", re.I),
        re.compile(rb"Directory Listing For", re.I),
        re.compile(rb"\[To Parent Directory\]", re.I),
    ]

    async def run(self, scanner):
        for d in self.DIRS:
            resp = await scanner.fetch(d)
            if resp is None or scanner.soft404.looks_like_404(resp):
                continue
            if resp["status"] == 200:
                for s in self.SIGNS:
                    if s.search(resp["body"]):
                        await scanner.add(Finding(
                            "medium", "0", f"Directory listing enabled at {d}",
                            resp["url"], evidence="Auto-index page detected",
                            tuning="3",
                        ))
                        break


DEFAULT_PLUGINS = [
    HttpMethodsPlugin(),
    DirectoryListingPlugin(),
    XSSReflectionPlugin(),
    SqlErrorPlugin(),
]


# ============================================================================
#  TLS / certificate / cipher inspection
# ============================================================================
class TLSInspector:
    WEAK_PROTOCOLS = {
        ssl.TLSVersion.SSLv3: ("critical", "SSLv3"),
        ssl.TLSVersion.TLSv1: ("high", "TLSv1.0"),
        ssl.TLSVersion.TLSv1_1: ("medium", "TLSv1.1"),
    }

    def __init__(self, host, port):
        self.host = host
        self.port = port

    async def inspect(self, scanner):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._inspect_blocking, scanner)

    def _add(self, scanner, finding):
        # schedule the coroutine on the loop from this worker thread context
        asyncio.run_coroutine_threadsafe(scanner.add(finding), scanner.loop)

    def _inspect_blocking(self, scanner):
        # 1. Pull and analyze the certificate
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()      # (name, protocol, bits)
                    proto = ssock.version()
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
            self._add(scanner, Finding(
                "info", "0", "TLS inspection failed / not available",
                f"https://{self.host}:{self.port}/", evidence=str(e), tuning="b"))
            return

        base = f"https://{self.host}:{self.port}/"

        # Negotiated protocol
        if proto in ("SSLv3", "TLSv1", "TLSv1.0"):
            self._add(scanner, Finding("high", "0",
                f"Server negotiated weak TLS protocol: {proto}", base,
                evidence=f"Negotiated {proto}", tuning="b"))
        elif proto == "TLSv1.1":
            self._add(scanner, Finding("medium", "0",
                f"Server negotiated deprecated protocol: {proto}", base,
                evidence=f"Negotiated {proto}", tuning="b"))

        # Cipher strength
        if cipher:
            name, cproto, bits = cipher
            if bits and bits < 128:
                self._add(scanner, Finding("high", "0",
                    f"Weak cipher negotiated: {name} ({bits}-bit)", base,
                    evidence=str(cipher), tuning="b"))
            weak_terms = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")
            if any(w in name.upper() for w in weak_terms):
                self._add(scanner, Finding("high", "0",
                    f"Insecure cipher suite in use: {name}", base,
                    evidence=str(cipher), tuning="b"))

        # Certificate analysis
        if cert:
            # Expiry
            not_after = cert.get("notAfter")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days = (exp - now).days
                    if days < 0:
                        self._add(scanner, Finding("high", "0",
                            "TLS certificate is EXPIRED", base,
                            evidence=f"Expired on {not_after}", tuning="b"))
                    elif days < 30:
                        self._add(scanner, Finding("medium", "0",
                            f"TLS certificate expires soon ({days} days)", base,
                            evidence=f"Expires {not_after}", tuning="b"))
                except ValueError:
                    pass

            # Hostname mismatch
            try:
                ssl.match_hostname(cert, self.host)
            except ssl.CertificateError as e:
                self._add(scanner, Finding("medium", "0",
                    "TLS certificate hostname mismatch", base,
                    evidence=str(e), tuning="b"))
            except Exception:
                pass

            # Self-signed (issuer == subject)
            subj = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            if subj and subj == issuer:
                self._add(scanner, Finding("medium", "0",
                    "TLS certificate appears self-signed", base,
                    evidence=f"Issuer == Subject ({subj.get('commonName','?')})",
                    tuning="b"))

        # Weak signature on the DER (very rough heuristic via length isn't reliable;
        # report key info instead)
        self._add(scanner, Finding("info", "0",
            f"TLS endpoint fingerprint: {proto} / {cipher[0] if cipher else '?'}",
            base, evidence=f"cert {len(der)} bytes", tuning="b"))


# ============================================================================
#  Core scanner
# ============================================================================
class FastScan:
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    SEV_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
               "low": "[LOW ]", "info": "[INFO]"}

    def __init__(self, config: ScanConfig, plugins=None):
        self.cfg = config
        self.findings: list[Finding] = []
        self.session: aiohttp.ClientSession | None = None
        self.soft404 = SoftNotFound()
        self.base, self.host, self.port, self.is_https = self._normalize_target(config)
        self.plugins = plugins if plugins is not None else DEFAULT_PLUGINS
        self._seen = set()
        self._lock = asyncio.Lock()
        self.loop = None
        self.detected_tech = []

    @staticmethod
    def _normalize_target(cfg: ScanConfig):
        target = cfg.target
        if not target.startswith(("http://", "https://")):
            scheme = "https" if cfg.ssl_force else "http"
            target = f"{scheme}://{target}"
        parsed = urlparse(target)
        host = parsed.hostname
        is_https = parsed.scheme == "https"
        port = cfg.port or parsed.port or (443 if is_https else 80)
        base = f"{parsed.scheme}://{host}:{port}"
        return base, host, port, is_https

    async def __aenter__(self):
        self.loop = asyncio.get_event_loop()
        ssl_ctx = None
        if self.is_https and not self.cfg.verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(
            limit=self.cfg.concurrency, ssl=ssl_ctx if self.is_https else None,
            ttl_dns_cache=300,
        )
        headers = {"User-Agent": self.cfg.user_agent}
        headers.update(self.cfg.headers)
        if self.cfg.cookies:
            headers["Cookie"] = self.cfg.cookies
        auth = None
        if self.cfg.auth and ":" in self.cfg.auth:
            u, _, p = self.cfg.auth.partition(":")
            auth = aiohttp.BasicAuth(u, p)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector, headers=headers, timeout=timeout, auth=auth,
        )
        return self

    async def __aexit__(self, *exc):
        if self.session:
            await self.session.close()

    # ---- tuning filter ----
    def _tuning_allows(self, category: str) -> bool:
        if not self.cfg.tuning:
            return True
        if "x" in self.cfg.tuning:           # reverse tuning
            return category not in self.cfg.tuning
        return category in self.cfg.tuning

    # ---- HTTP helper ----
    async def fetch(self, path_or_url: str, method: str = "GET"):
        url = path_or_url if path_or_url.startswith("http") else self.base + path_or_url
        try:
            async with self.session.request(
                method, url, allow_redirects=self.cfg.follow_redirects,
                max_redirects=self.cfg.max_redirects,
            ) as r:
                body = await r.read()
                return {
                    "url": str(r.url), "status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body, "length": len(body),
                    "body_hash": hashlib.md5(body[:4096]).hexdigest(),
                    "method": method,
                }
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
            return None
        except Exception:
            return None

    async def add(self, finding: Finding):
        async with self._lock:
            key = (finding.title, finding.url)
            if key not in self._seen:
                self._seen.add(key)
                self.findings.append(finding)
                self._print_finding(finding)

    # ---- baseline / headers ----
    async def check_baseline(self):
        resp = await self.fetch("/")
        if resp is None:
            print(f"+ ERROR: Could not connect to {self.base}")
            return False

        h = resp["headers"]
        srv = h.get("server", "Unknown")
        print(f"+ Target IP:        {self._resolve_ip()}")
        print(f"+ Target Hostname:  {self.host}")
        print(f"+ Target Port:      {self.port}")
        print(f"+ Server:           {srv}")
        print(f"+ Start Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 76)

        if self._tuning_allows("b"):
            for hdr in VERSION_HEADERS:
                if hdr in h and h[hdr].strip():
                    sev = "medium" if re.search(r"\d+\.\d+", h[hdr]) else "low"
                    await self.add(Finding(
                        sev, "0", f"Software/version disclosed via '{hdr}' header",
                        resp["url"], evidence=f"{hdr}: {h[hdr]}", tuning="b"))

        if self._tuning_allows("2"):
            for hdr, (sev, desc) in SECURITY_HEADERS.items():
                if hdr == "strict-transport-security" and not self.is_https:
                    continue
                if hdr not in h:
                    await self.add(Finding(sev, "0", desc, resp["url"],
                                           evidence=f"Header '{hdr}' not present", tuning="2"))

            set_cookie = h.get("set-cookie", "")
            if set_cookie:
                low = set_cookie.lower()
                if self.is_https and "secure" not in low:
                    await self.add(Finding("low", "0", "Cookie set without 'Secure' flag",
                                           resp["url"], evidence=set_cookie[:120], tuning="2"))
                if "httponly" not in low:
                    await self.add(Finding("low", "0", "Cookie set without 'HttpOnly' flag",
                                           resp["url"], evidence=set_cookie[:120], tuning="2"))
        return True

    def _resolve_ip(self):
        try:
            return socket.gethostbyname(self.host)
        except OSError:
            return "unknown"

    # ---- CMS fingerprinting ----
    async def fingerprint_cms(self):
        root = await self.fetch("/")
        root_body = root["body"] if root else b""
        root_headers = root["headers"] if root else {}

        for fp in CMS_FINGERPRINTS:
            score = 0
            matched_path = None

            for pat in fp.get("body", []):
                if pat.search(root_body):
                    score += 2

            for hdr, pat in fp.get("header", {}).items():
                val = root_headers.get(hdr, "")
                if val and (pat is None or pat.search(val)):
                    score += 1

            for p in fp["paths"]:
                resp = await self.fetch(p)
                if resp and not self.soft404.looks_like_404(resp) and resp["status"] in (200, 401, 403):
                    score += 1
                    matched_path = p
                    if resp["status"] == 200:
                        for pat in fp.get("body", []):
                            if pat.search(resp["body"]):
                                score += 1

            if score >= 2:
                self.detected_tech.append(fp["name"])
                version = await self._detect_cms_version(fp)
                vtext = f" version {version}" if version else ""
                await self.add(Finding(
                    "info", "0", f"{fp['name']} detected{vtext}",
                    self.base, evidence=f"confidence score={score}, path={matched_path}",
                    tuning="b"))

    async def _detect_cms_version(self, fp):
        vpath = fp.get("version_path")
        if not vpath:
            return None
        resp = await self.fetch(vpath)
        if not resp or resp["status"] != 200:
            return None
        for key in ("version_path_re", "version"):
            pat = fp.get(key)
            if pat:
                m = pat.search(resp["body"])
                if m:
                    return m.group(1).decode(errors="ignore")
        return None

    # ---- path probing ----
    async def probe_path(self, path, osvdb, desc, severity, tuning):
        if not self._tuning_allows(tuning):
            return
        if self.cfg.rate_limit:
            await asyncio.sleep(self.cfg.rate_limit)
        resp = await self.fetch(path)
        if resp is None or self.soft404.looks_like_404(resp):
            return

        status = resp["status"]
        confirmed = None
        confirmed_sev = None
        for pattern, label, csev in INTERESTING_CONTENT:
            if pattern.search(resp["body"]):
                confirmed, confirmed_sev = label, csev
                break

        if status == 200:
            evidence = f"HTTP 200 ({resp['length']} bytes)"
            sev = severity
            if confirmed:
                evidence += f" | confirmed: {confirmed}"
                sev = confirmed_sev or severity
            await self.add(Finding(sev, osvdb, desc, resp["url"],
                                   evidence=evidence, tuning=tuning))
        elif status in (401, 403):
            await self.add(Finding("info", osvdb, f"{desc} (exists, protected)",
                                   resp["url"], evidence=f"HTTP {status}", tuning=tuning))
        elif status in (301, 302, 307, 308) and not self.cfg.follow_redirects:
            loc = resp["headers"].get("location", "")
            await self.add(Finding("info", osvdb, f"{desc} (redirect)",
                                   resp["url"], evidence=f"HTTP {status} -> {loc}", tuning=tuning))

    async def check_paths(self, paths):
        sem = asyncio.Semaphore(self.cfg.concurrency)

        async def worker(entry):
            async with sem:
                await self.probe_path(*entry)

        await asyncio.gather(*(worker(e) for e in paths))

    def _load_wordlist(self):
        paths = list(DEFAULT_PATHS)
        if self.cfg.wordlist:
            try:
                with open(self.cfg.wordlist, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        p = line if line.startswith("/") else "/" + line
                        paths.append((p, "0", f"Wordlist path: {p}", "info", "1"))
            except OSError as e:
                print(f"+ ERROR: Could not read wordlist: {e}")
        return paths

    # ---- orchestration ----
    async def run(self):
        start = time.time()
        print(BANNER)

        ok = await self.check_baseline()
        if not ok:
            return

        await self.soft404.calibrate(self)

        # TLS inspection
        if self.is_https and not self.cfg.no_tls_scan and self._tuning_allows("b"):
            print("+ Running TLS/certificate inspection...")
            await TLSInspector(self.host, self.port).inspect(self)

        # CMS fingerprinting
        if not self.cfg.no_cms_scan and self._tuning_allows("b"):
            print("+ Fingerprinting CMS / technology...")
            await self.fingerprint_cms()

        # Plugins
        if self.cfg.plugins_enabled and self.plugins:
            print(f"+ Running {len(self.plugins)} plugins...")
            plugin_tasks = [p.run(self) for p in self.plugins if self._tuning_allows(p.tuning)]
            await asyncio.gather(*plugin_tasks)

        # Path probing
        paths = self._load_wordlist()
        print(f"+ Probing {len(paths)} paths...")
        await self.check_paths(paths)

        elapsed = time.time() - start
        print("-" * 76)
        print(f"+ {len(self.findings)} item(s) reported on remote host")
        print(f"+ End Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
              f"({elapsed:.1f} seconds)")
        print("-" * 76)
        self._report()

    # ---- reporting ----
    def _print_finding(self, f: Finding):
        tag = self.SEV_TAG.get(f.severity, "[????]")
        osv = f"OSVDB-{f.osvdb}: " if f.osvdb and f.osvdb != "0" else ""
        line = f"+ {tag} {osv}{f.title}"
        path = urlparse(f.url).path or "/"
        line += f"  ({f.method} {path})"
        print(line)
        if f.evidence:
            print(f"         {f.evidence}")

    def _report(self):
        ordered = sorted(self.findings, key=lambda x: self.SEV_ORDER.get(x.severity, 9))
        if self.cfg.output:
            try:
                fmt = self.cfg.output_format
                if fmt == "json":
                    self._write_json(ordered)
                elif fmt == "csv":
                    self._write_csv(ordered)
                elif fmt == "html":
                    self._write_html(ordered)
                else:
                    self._write_text(ordered)
                print(f"+ Report written to {self.cfg.output} ({fmt})")
            except OSError as e:
                print(f"+ ERROR: Could not write report: {e}")

        counts = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("\n=== Severity Summary ===")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in counts:
                print(f"  {self.SEV_TAG[sev]} {counts[sev]}")

    def _write_json(self, ordered):
        data = {
            "scanner": f"FastScan {VERSION}",
            "target": self.base,
            "host": self.host,
            "port": self.port,
            "technologies": self.detected_tech,
            "scanned_at": datetime.now().isoformat(),
            "findings": [f.to_dict() for f in ordered],
        }
        with open(self.cfg.output, "w") as fh:
            json.dump(data, fh, indent=2)

    def _write_csv(self, ordered):
        with open(self.cfg.output, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["severity", "id", "title", "method", "url", "evidence", "tuning"])
            for f in ordered:
                w.writerow([f.severity, f.osvdb, f.title, f.method, f.url, f.evidence, f.tuning])

    def _write_text(self, ordered):
        with open(self.cfg.output, "w") as fh:
            fh.write(f"FastScan {VERSION} report for {self.base}\n")
            fh.write(f"Generated {datetime.now().isoformat()}\n")
            if self.detected_tech:
                fh.write(f"Technologies: {', '.join(self.detected_tech)}\n")
            fh.write("\n")
            for f in ordered:
                osv = f"OSVDB-{f.osvdb}: " if f.osvdb != "0" else ""
                fh.write(f"{self.SEV_TAG.get(f.severity)} {osv}{f.title}\n")
                fh.write(f"    {f.method} {f.url}\n")
                if f.evidence:
                    fh.write(f"    Evidence: {f.evidence}\n")
                fh.write("\n")

    def _write_html(self, ordered):
        color = {"critical": "#c0392b", "high": "#e74c3c", "medium": "#e67e22",
                 "low": "#f1c40f", "info": "#3498db"}
        rows = []
        for f in ordered:
            c = color.get(f.severity, "#999")
            osv = f"OSVDB-{f.osvdb}: " if f.osvdb != "0" else ""
            rows.append(f"""
            <tr>
              <td><span style="background:{c};color:#fff;padding:2px 8px;
                  border-radius:4px;font-size:12px;">{f.severity.upper()}</span></td>
              <td>{osv}{_html_escape(f.title)}</td>
              <td>{f.method}</td>
              <td><code>{_html_escape(f.url)}</code></td>
              <td>{_html_escape(f.evidence)}</td>
            </tr>""")
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>FastScan Report - {_html_escape(self.host)}</title>
<style>
 body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#222;}}
 h1{{color:#2c3e50;}} table{{border-collapse:collapse;width:100%;}}
 th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:14px;}}
 th{{background:#2c3e50;color:#fff;}} tr:nth-child(even){{background:#f7f7f7;}}
 code{{background:#eee;padding:1px 4px;border-radius:3px;word-break:break-all;}}
 .meta{{color:#555;margin-bottom:16px;}}
</style></head><body>
<h1>FastScan {VERSION} Report</h1>
<div class="meta">
 <b>Target:</b> {_html_escape(self.base)}<br>
 <b>Host:</b> {_html_escape(self.host)} &nbsp; <b>Port:</b> {self.port}<br>
 <b>Technologies:</b> {_html_escape(', '.join(self.detected_tech) or 'none detected')}<br>
 <b>Generated:</b> {datetime.now().isoformat()}<br>
 <b>Total findings:</b> {len(ordered)}
</div>
<table>
 <tr><th>Severity</th><th>Finding</th><th>Method</th><th>URL</th><th>Evidence</th></tr>
 {''.join(rows)}
</table>
</body></html>"""
        with open(self.cfg.output, "w") as fh:
            fh.write(html)


def _html_escape(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ============================================================================
#  CLI
# ============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="FastScan - fast Nikto-style async web scanner (authorized use only)",
        epilog="Tuning categories: " + "; ".join(f"{k}={v}" for k, v in TUNING.items()),
    )
    p.add_argument("-h", "--host", dest="target", required=True,
                   help="Target host or URL (Nikto-style -h)")
    p.add_argument("-p", "--port", type=int, default=0, help="Target port")
    p.add_argument("-s", "--ssl", action="store_true", dest="ssl_force",
                   help="Force SSL/TLS")
    p.add_argument("-c", "--concurrency", type=int, default=50,
                   help="Concurrent requests (default 50)")
    p.add_argument("-t", "--timeout", type=float, default=10.0,
                   help="Per-request timeout (s)")
    p.add_argument("-w", "--wordlist", default="", help="Extra path wordlist file")
    p.add_argument("-o", "--output", default="", help="Write report to file")
    p.add_argument("-F", "--format", choices=["text", "json", "csv", "html"],
                   default="text", dest="output_format", help="Report format")
    p.add_argument("-T", "--tuning", default="",
                   help="Restrict to tuning categories (e.g. '235e'); 'x' = reverse")
    p.add_argument("-A", "--user-agent",
                   default="Mozilla/5.0 (FastScan/%s; +authorized-testing)" % VERSION)
    p.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verify (default)")
    p.add_argument("--verify-ssl", action="store_true", help="Verify TLS certs")
    p.add_argument("--no-redirect", action="store_true", help="Don't follow redirects")
    p.add_argument("--no-tls-scan", action="store_true", help="Skip TLS inspection")
    p.add_argument("--no-cms-scan", action="store_true", help="Skip CMS fingerprinting")
    p.add_argument("--no-plugins", action="store_true", help="Disable plugins")
    p.add_argument("--cookie", default="", help="Cookie header value")
    p.add_argument("--auth", default="", help="HTTP basic auth 'user:pass'")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Extra header 'Name: Value' (repeatable)")
    p.add_argument("--rate-limit", type=float, default=0.0,
                   help="Delay (s) between requests per worker")
    return p.parse_args()


def build_config(args) -> ScanConfig:
    extra_headers = {}
    for hdr in args.header:
        if ":" in hdr:
            name, _, val = hdr.partition(":")
            extra_headers[name.strip()] = val.strip()
    return ScanConfig(
        target=args.target, port=args.port, ssl_force=args.ssl_force,
        concurrency=args.concurrency, timeout=args.timeout,
        user_agent=args.user_agent, verify_ssl=args.verify_ssl,
        follow_redirects=not args.no_redirect, cookies=args.cookie,
        headers=extra_headers, auth=args.auth, output=args.output,
        output_format=args.output_format, wordlist=args.wordlist,
        rate_limit=args.rate_limit, tuning=args.tuning,
        no_tls_scan=args.no_tls_scan, no_cms_scan=args.no_cms_scan,
        plugins_enabled=not args.no_plugins,
    )


async def main_async():
    args = parse_args()
    config = build_config(args)
    async with FastScan(config) as scanner:
        await scanner.run()


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n+ Scan interrupted by user.")


if __name__ == "__main__":
    main()
