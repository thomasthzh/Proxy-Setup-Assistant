"""Conservative, repeatable installer for an otherwise unused Debian/Ubuntu VPS.

Run from the extracted payload: python3 -m server.installer --config input.json.
--plan validates inputs and prints a public plan without executing any command.
Only install() and certificate deployment mutate the machine. All commands use
argument arrays; captured command output is never included in public errors.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

ETC = Path('/etc/vps-proxy-setup')
OPT = Path('/opt/vps-proxy-setup')
APP = OPT / 'app'
DATA = Path('/var/lib/vps-proxy-setup')
ACME = ETC / 'acme'
WEBROOT = Path('/var/lib/vpsproxy-acme')
UNITS = Path('/etc/systemd/system')
TAILSCALE_KEY = Path('/usr/share/keyrings/vpsproxy-tailscale.gpg')
TAILSCALE_SOURCE = Path('/etc/apt/sources.list.d/vpsproxy-tailscale.list')
MARKER = 'Managed by VPS-Proxy-SetUP schema 1'
CERT_NAME = 'vpsproxy'
SUPPORTED = {('debian', '12'): 'bookworm', ('debian', '13'): 'trixie',
             ('ubuntu', '22.04'): 'jammy', ('ubuntu', '24.04'): 'noble'}
USERS = ('vpsproxy-hy2', 'vpsproxy-xray', 'vpsproxy-web', 'vpsproxy-sub')
SERVICE_NAMES = ('vpsproxy-nginx', 'vpsproxy-hy2', 'vpsproxy-xray', 'vpsproxy-sub',
                 'vpsproxy-refresh', 'vpsproxy-renew')
# Prevent authenticated clients from reaching host services, private networks,
# link-local cloud metadata endpoints, multicast, and address-translation ranges.
PRIVATE_CIDRS = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                 '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
                 '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
                 '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96',
                 '64:ff9b:1::/48', 'fc00::/7', 'fe80::/10', 'ff00::/8')


class InstallError(Exception):
    """Safe, deliberately non-secret-bearing operational error."""


def validate_config(value: object) -> dict:
    if not isinstance(value, dict):
        raise InstallError('Configuration must be a JSON object.')
    allowed = {'schema_version', 'label', 'address', 'tls_name', 'email',
               'acme_accept_terms', 'ports', 'tailscale', 'tune'}
    if set(value) - allowed:
        raise InstallError('Configuration contains unsupported fields.')
    cfg = dict(value)
    if type(cfg.get('schema_version')) is not int or cfg['schema_version'] != 1:
        raise InstallError('Only configuration schema 1 is supported.')
    if not isinstance(cfg.get('label'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', cfg['label']):
        raise InstallError('Label must be 1–32 ASCII letters, digits, underscores or hyphens.')
    address = cfg.get('address')
    if not isinstance(address, str) or len(address) > 253:
        raise InstallError('Address must be a public IPv4 address or DNS hostname.')
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        if ('.' not in address or address.endswith('.') or
                not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                        for part in address.split('.')) or
                not re.search(r'[A-Za-z]', address.rsplit('.', 1)[-1])):
            raise InstallError('Address must be a valid public DNS hostname.') from None
        cfg['address'] = address.lower()
    else:
        if ip.version != 4 or not ip.is_global:
            raise InstallError('Only globally routable IPv4 addresses are supported.')
        cfg['address'] = str(ip)
    if not isinstance(cfg.get('tls_name', address), str) or cfg.get('tls_name', address).lower() != cfg['address']:
        raise InstallError('TLS name must match the public address in schema 1.')
    cfg['tls_name'] = cfg['address']
    email = cfg.setdefault('email', '')
    if not isinstance(email, str) or (email and not re.fullmatch(r'[^\s@\x00-\x1f]+@[^\s@\x00-\x1f]+\.[^\s@\x00-\x1f]+', email)):
        raise InstallError('Email must be empty or a valid email address.')
    if cfg.get('acme_accept_terms') is not True:
        raise InstallError('Explicit acceptance of the ACME subscriber agreement is required.')
    ports = cfg.get('ports')
    if not isinstance(ports, dict) or set(ports) != {'https', 'hy2', 'trojan'}:
        raise InstallError('ports must contain https, hy2 and trojan.')
    if any(type(port) is not int or not 1024 <= port <= 65535 or port == 18081 for port in ports.values()):
        raise InstallError('Ports must be integers from 1024–65535, excluding internal port 18081.')
    if ports['https'] == ports['trojan']:
        raise InstallError('HTTPS and Trojan require distinct TCP ports.')
    cfg['ports'] = dict(ports)
    for name, default in (('tailscale', False), ('tune', True)):
        if type(cfg.setdefault(name, default)) is not bool:
            raise InstallError(name + ' must be a JSON boolean.')
    return cfg


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True) + '\n'


def read_json(path: Path) -> dict:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise InstallError('JSON input is too large.')
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise InstallError('Could not read valid JSON input.') from None
    if not isinstance(value, dict):
        raise InstallError('Expected a JSON object.')
    return value


def build_settings(config: dict, existing: dict | None = None) -> dict:
    cfg = validate_config(config)
    if existing is not None:
        for field in ('schema_version', 'address', 'tls_name', 'ports'):
            if existing.get(field) != cfg[field]:
                raise InstallError('Existing address, TLS name and ports cannot be changed by a rerun.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', str(existing.get('token', ''))):
            raise InstallError('Existing settings are incomplete; refusing to rotate credentials.')
        if not isinstance(existing.get('clients'), dict):
            raise InstallError('Existing settings are incomplete; refusing to rotate credentials.')
        for device in ('windows', 'iphone'):
            client = existing.get('clients', {}).get(device, {})
            if (not isinstance(client, dict) or
                    not re.fullmatch(device + r':[A-Za-z0-9_-]{32,128}', str(client.get('hy2_auth', ''))) or
                    not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', str(client.get('trojan_password', '')))):
                raise InstallError('Existing settings are incomplete; refusing to rotate credentials.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', str(existing.get('hy2_obfs', ''))):
            raise InstallError('Existing settings are incomplete; refusing to rotate credentials.')
        result = {**existing, **cfg}
    else:
        result = {**cfg, 'token': secrets.token_urlsafe(32),
                  'hy2_obfs': secrets.token_urlsafe(32),
                  'clients': {device: {'hy2_auth': device + ':' + secrets.token_urlsafe(32),
                                       'trojan_password': secrets.token_urlsafe(32)}
                              for device in ('windows', 'iphone')}}
    result['hy2_port'] = cfg['ports']['hy2']
    result['trojan_port'] = cfg['ports']['trojan']
    result['base_url'] = 'https://{}:{}/s/{}'.format(cfg['address'], cfg['ports']['https'], result['token'])
    return result


def plan(config: dict) -> dict:
    cfg = validate_config(config)
    assets = read_json(Path(__file__).with_name('assets.json'))
    return {'schema_version': 1, 'mode': 'plan', 'address': cfg['address'],
            'ports': cfg['ports'], 'required_tcp_ports': [80, cfg['ports']['https'], cfg['ports']['trojan']],
            'required_udp_ports': [cfg['ports']['hy2']],
            'subscription_listener': '127.0.0.1:18081',
            'certificate': 'Let\'s Encrypt HTTP-01; shortlived profile for IPv4; reusable key',
            'versions': {name: assets[name]['version'] for name in ('hysteria', 'xray', 'certbot')},
            'tailscale': cfg['tailscale'], 'tune': cfg['tune'],
            'steps': ['Check root, supported OS, systemd, ownership and listening ports',
                      'Install distro dependencies and verified pinned transport binaries',
                      'Create dedicated service accounts and preserve persistent credentials',
                      'Serve HTTP-01 on TCP 80 and obtain a trusted TLS certificate',
                      'Validate configs; start HY2, Trojan and HTTPS subscriptions',
                      'Enable certificate renewal and rule refresh timers',
                      'Check local listeners and write private result.json'],
            'note': 'Plan makes no changes, performs no network requests and generates no credentials.'}


def run(args: list[str], *, check: bool = True, timeout: int = 300,
        input_data: str | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run([str(x) for x in args], input=input_data, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InstallError('A required command failed or timed out: ' + Path(args[0]).name) from None
    if check and result.returncode:
        raise InstallError('A required command failed: ' + Path(args[0]).name +
                           '. Inspect the corresponding service or private ACME log on the server.')
    return result


def ensure_dir(path: Path, mode: int = 0o755, group: str | None = None) -> None:
    if path.is_symlink():
        raise InstallError('Refusing a symlink in an installation directory.')
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    if group:
        shutil.chown(path, user='root', group=group)


def atomic_write(path: Path, data: str | bytes, mode: int = 0o600,
                 group: str | None = None) -> None:
    if path.is_symlink():
        raise InstallError('Refusing to overwrite a symlink.')
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    tmp = Path(name)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, mode)
        else:  # Allows filesystem tests and --plan on Windows developer hosts.
            tmp.chmod(mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data.encode('utf-8') if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        if group:
            shutil.chown(tmp, user='root', group=group)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def os_release(path: Path = Path('/etc/os-release')) -> tuple[str, str, str]:
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"\'')
    pair = (values.get('ID', ''), values.get('VERSION_ID', ''))
    if pair not in SUPPORTED:
        raise InstallError('Supported systems: Debian 12/13 or Ubuntu 22.04/24.04.')
    return pair[0], pair[1], SUPPORTED[pair]


def architecture() -> str:
    machine = platform.machine().lower()
    if machine in ('x86_64', 'amd64'):
        return 'amd64'
    if machine in ('aarch64', 'arm64'):
        return 'arm64'
    raise InstallError('Only amd64 and arm64 servers are supported.')


def expected_listeners(cfg: dict) -> dict[tuple[str, int], str]:
    return {('tcp', 80): 'vpsproxy-nginx.service',
            ('tcp', cfg['ports']['https']): 'vpsproxy-nginx.service',
            ('tcp', cfg['ports']['trojan']): 'vpsproxy-xray.service',
            ('tcp', 18081): 'vpsproxy-sub.service',
            ('udp', cfg['ports']['hy2']): 'vpsproxy-hy2.service'}


def check_listeners(cfg: dict, listing: str, *, managed: bool,
                    cgroup_reader=None) -> None:
    expected = expected_listeners(cfg)
    if cgroup_reader is None:
        cgroup_reader = lambda pid: Path('/proc', pid, 'cgroup').read_text()
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ('tcp', 'udp'):
            continue
        try:
            port = int(fields[4].rsplit(':', 1)[-1])
        except ValueError:
            continue
        key = (fields[0], port)
        if key not in expected:
            continue
        pids = re.findall(r'pid=(\d+)', line)
        owned = managed and bool(pids)
        for pid in pids:
            try:
                groups = cgroup_reader(pid)
                owned = owned and any(part == expected[key] for part in re.split(r'[/\n]', groups))
            except OSError:
                owned = False
        if not owned:
            raise InstallError('An unmanaged listener occupies required {} port {}.'.format(*key))


def preflight(cfg: dict) -> tuple[bool, tuple[str, str, str]]:
    if sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0:
        raise InstallError('Installation requires root on Linux; use --plan for a local preview.')
    distro = os_release()
    architecture()
    if not Path('/run/systemd/system').is_dir():
        raise InstallError('A booted systemd host is required.')
    for command in ('systemctl', 'ss', 'apt-get', 'runuser', 'openssl'):
        if not shutil.which(command):
            package = {'ss': 'iproute2', 'openssl': 'openssl', 'runuser': 'util-linux',
                       'systemctl': 'systemd', 'apt-get': 'apt'}[command]
            raise InstallError('Missing prerequisite command: ' + command +
                               '. Install the base package first: apt-get install ' + package)
    managed = (ETC / 'managed-by').is_file() and (ETC / 'managed-by').read_text() == MARKER + '\n'
    for path in (ETC, OPT, DATA, WEBROOT):
        if path.is_symlink() or (path.exists() and not managed):
            raise InstallError('An installation path already exists without our ownership marker.')
    for name in SERVICE_NAMES:
        for suffix in ('.service', '.timer'):
            unit = UNITS / (name + suffix)
            if unit.exists() and (not managed or unit.is_symlink() or MARKER not in unit.read_text()):
                raise InstallError('A reserved service name is already in use.')
            fragment = run(['systemctl', 'show', name + suffix, '-p', 'FragmentPath', '--value'], check=False).stdout.strip()
            if fragment and fragment != str(unit):
                raise InstallError('A reserved service name is already in use.')
    if not managed:
        if shutil.which('nginx') or run(['systemctl', 'show', 'nginx.service', '-p', 'FragmentPath', '--value'], check=False).stdout.strip():
            raise InstallError('This installer requires a fresh host without an existing nginx installation.')
        for user in (*USERS, 'vpsproxy-tls'):
            if run(['getent', 'passwd', user], check=False).returncode == 0 or run(['getent', 'group', user], check=False).returncode == 0:
                raise InstallError('A reserved service account or group already exists.')
    elif run(['systemctl', 'is-active', '--quiet', 'nginx.service'], check=False).returncode == 0:
        raise InstallError('The distro nginx service is active; refusing to disrupt it.')
    # Tailscale is optional; never take over an administrator's existing daemon.
    if cfg['tailscale'] and not (ETC / 'tailscale-owned').exists():
        if shutil.which('tailscale') or Path('/etc/apt/sources.list.d/tailscale.list').exists():
            raise InstallError('Tailscale already exists; rerun with tailscale=false and manage it separately.')
    check_listeners(cfg, run(['ss', '-H', '-lntup']).stdout, managed=managed)
    return managed, distro


@contextlib.contextmanager
def install_lock():
    import fcntl
    # /run is root owned; a nonblocking lock also prevents simultaneous renewal.
    path = '/run/vpsproxy-install.lock'
    with open(path, 'a', encoding='ascii') as stream:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('Another installation or certificate deployment is running.') from None
        yield


def install_dependencies() -> None:
    # Suppress the NEW distro nginx unit during apt installation. This is a
    # runtime mask, and preflight already ruled out existing nginx installations.
    # This package belongs to this installation (also on a rerun). Keep its
    # general-purpose service disabled; only vpsproxy-nginx uses the binary.
    run(['systemctl', 'mask', '--runtime', 'nginx.service'])
    try:
        env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'}
        run(['apt-get', 'update'], env=env, timeout=900)
        run(['apt-get', 'install', '-y', '--no-install-recommends',
             'ca-certificates', 'nginx', 'python3-venv', 'openssl', 'iproute2', 'util-linux'], env=env, timeout=1200)
        run(['systemctl', 'disable', 'nginx.service'])
    finally:
        run(['systemctl', 'unmask', '--runtime', 'nginx.service'], check=False)
    if not (OPT / 'certbot/bin/python').exists():
        run(['/usr/bin/python3', '-m', 'venv', str(OPT / 'certbot')])
    run([str(OPT / 'certbot/bin/python'), '-m', 'pip', 'install', '--disable-pip-version-check',
         '--index-url', 'https://pypi.org/simple', 'certbot==5.8.0'], timeout=900)


def create_accounts() -> None:
    for group in (*USERS, 'vpsproxy-tls'):
        if run(['getent', 'group', group], check=False).returncode:
            run(['groupadd', '--system', group])
    for user in USERS:
        if run(['getent', 'passwd', user], check=False).returncode:
            run(['useradd', '--system', '--gid', user, '--home-dir', '/nonexistent',
                 '--no-create-home', '--shell', '/usr/sbin/nologin', user])
        if user != 'vpsproxy-sub':
            run(['usermod', '--append', '--groups', 'vpsproxy-tls', user])


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise InstallError('Refusing an insecure download redirect.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, *, sha256: str | None = None, max_bytes: int = 128 * 1024 * 1024) -> bytes:
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise InstallError('Downloads require HTTPS.')
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'VPS-Proxy-SetUP/1'})
        with urllib.request.build_opener(HTTPSOnly).open(request, timeout=120) as response:
            data = response.read(max_bytes + 1)
    except (OSError, ValueError):
        raise InstallError('An upstream download failed; existing binaries were not replaced.') from None
    if len(data) > max_bytes:
        raise InstallError('An upstream download exceeded its size limit.')
    if sha256 is not None and not secrets.compare_digest(hashlib.sha256(data).hexdigest(), sha256):
        raise InstallError('Upstream binary SHA256 mismatch; refusing to install.')
    return data


def install_binaries() -> None:
    import io
    assets = read_json(Path(__file__).with_name('assets.json'))
    arch = architecture()
    ensure_dir(OPT / 'bin')
    for product in ('hysteria', 'xray'):
        item = assets[product][arch]
        destination = OPT / 'bin' / product
        receipt = destination.with_suffix('.sha256')
        # The receipt records the extracted executable hash, not just ZIP hash.
        if destination.exists() and receipt.exists():
            recorded = receipt.read_text().splitlines()
            if len(recorded) == 2 and recorded[0] == item['sha256'] and hashlib.sha256(destination.read_bytes()).hexdigest() == recorded[1]:
                continue
        payload = download(item['url'], sha256=item['sha256'])
        if product == 'xray':
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    info = archive.getinfo('xray')
                    if info.file_size > 128 * 1024 * 1024:
                        raise InstallError('Unexpected Xray executable size.')
                    payload = archive.read(info)
            except (KeyError, zipfile.BadZipFile):
                raise InstallError('Verified Xray archive has an unexpected layout.') from None
        if not payload.startswith(b'\x7fELF'):
            raise InstallError('Expected a Linux ELF executable.')
        atomic_write(destination, payload, 0o755)
        atomic_write(receipt, item['sha256'] + '\n' + hashlib.sha256(payload).hexdigest() + '\n')


def copy_application() -> None:
    source = Path(__file__).resolve().parent
    destination = APP / 'server'
    ensure_dir(APP)
    ensure_dir(destination)
    if not (source / 'subscription/refresh.py').is_file() or not (source / 'subscription/http_server.py').is_file():
        raise InstallError('Payload is missing subscription modules.')
    for file in source.rglob('*'):
        if file.is_symlink():
            raise InstallError('Payload must not contain symlinks.')
        if file.is_file() and file.suffix in ('.py', '.json') and '__pycache__' not in file.parts:
            target = destination / file.relative_to(source)
            ensure_dir(target.parent)
            if file.resolve() != target.resolve():
                atomic_write(target, file.read_bytes(), 0o644)


def host_addresses(settings: dict) -> list[str]:
    """Resolve both configured public names and assigned host interfaces."""
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(settings['address'], None)}
        interfaces = json.loads(run(['ip', '-j', 'address', 'show']).stdout)
        for interface in interfaces:
            for value in interface.get('addr_info', []):
                if value.get('family') in ('inet', 'inet6'):
                    addresses.add(value['local'])
        return sorted(str(ipaddress.ip_address(item)) for item in addresses)
    except (OSError, ValueError, KeyError):
        raise InstallError('Could not determine server addresses for outbound access restrictions.') from None


def transport_configs(settings: dict, server_ips: list[str] | None = None) -> dict[str, dict]:
    cert = str(ETC / 'tls/current/fullchain.pem')
    key = str(ETC / 'tls/current/privkey.pem')
    blocked = list(PRIVATE_CIDRS)
    for value in server_ips or []:
        ip = ipaddress.ip_address(value)
        blocked.append(str(ip) + ('/32' if ip.version == 4 else '/128'))
    try:
        ip = ipaddress.ip_address(settings['address'])
        blocked.append(str(ip) + '/32')
    except ValueError:
        pass
    blocked = list(dict.fromkeys(blocked))
    keepalive = {'tcpKeepAliveIdle': 30, 'tcpKeepAliveInterval': 15}
    hy2 = {'listen': '0.0.0.0:' + str(settings['hy2_port']),
           'tls': {'cert': cert, 'key': key, 'sniGuard': 'dns-san'},
           'obfs': {'type': 'salamander', 'salamander': {'password': settings['hy2_obfs']}},
           'auth': {'type': 'userpass', 'userpass': {
               device: value['hy2_auth'].split(':', 1)[1] for device, value in settings['clients'].items()}},
           'acl': {'inline': ['reject(' + network + ')' for network in blocked] +
                             ['reject(' + settings['address'] + ')', 'direct(all)']},
           'outbounds': [{'name': 'direct', 'type': 'direct', 'direct': {'mode': '46'}}],
           'ignoreClientBandwidth': True, 'disableUDP': False,
           'masquerade': {'type': 'string', 'string': {'content': 'Not Found', 'statusCode': 404}}}
    xray = {'log': {'access': 'none', 'error': 'none', 'loglevel': 'none'},
            'inbounds': [{'tag': 'trojan', 'listen': '0.0.0.0', 'port': settings['trojan_port'],
                          'protocol': 'trojan',
                          'settings': {'clients': [{'password': client['trojan_password'], 'email': device}
                                                   for device, client in settings['clients'].items()]},
                          'streamSettings': {'network': 'tcp', 'security': 'tls', 'sockopt': keepalive, 'tlsSettings': {
                              'minVersion': '1.2', 'alpn': ['http/1.1'],
                              'certificates': [{'certificateFile': cert, 'keyFile': key,
                                                'oneTimeLoading': False, 'usage': 'encipherment'}]}}}],
            'dns': {'servers': ['localhost']},
            'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
                # Xray unmaps IPv4-mapped IPv6 before its CIDR parser, and
                # rejects a /96 there; ordinary IPv4 rules cover those targets.
                {'type': 'field', 'ip': [network for network in blocked if network != '::ffff:0:0/96'], 'outboundTag': 'blocked'},
                {'type': 'field', 'domain': ['full:' + settings['address']], 'outboundTag': 'blocked'}]},
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct',
                           'settings': {'domainStrategy': 'UseIPv4v6'},
                           'streamSettings': {'sockopt': keepalive}},
                          {'protocol': 'blackhole', 'tag': 'blocked'}]}
    return {'hysteria.json': hy2, 'xray.json': xray}


def nginx_config(settings: dict, *, tls: bool) -> str:
    https = ''
    if tls:
        https = f'''
    server {{
        listen 0.0.0.0:{settings['ports']['https']} ssl;
        server_name {settings['address']};
        ssl_certificate {ETC}/tls/current/fullchain.pem;
        ssl_certificate_key {ETC}/tls/current/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout 10m;
        add_header Cache-Control "no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        location / {{
            limit_req zone=subscriptions burst=40 nodelay;
            proxy_pass http://127.0.0.1:18081;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_connect_timeout 3s;
            proxy_read_timeout 15s;
            proxy_buffering off;
        }}
    }}
'''
    return f'''# {MARKER}
worker_processes auto;
pid /run/vpsproxy-nginx/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    error_log /dev/null crit;
    server_tokens off;
    default_type application/octet-stream;
    client_max_body_size 1k;
    client_body_temp_path /run/vpsproxy-nginx/client;
    proxy_temp_path /run/vpsproxy-nginx/proxy;
    fastcgi_temp_path /run/vpsproxy-nginx/fastcgi;
    uwsgi_temp_path /run/vpsproxy-nginx/uwsgi;
    scgi_temp_path /run/vpsproxy-nginx/scgi;
    limit_req_zone $binary_remote_addr zone=subscriptions:1m rate=10r/s;
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_types application/yaml application/json text/plain;
    server {{
        listen 0.0.0.0:80;
        server_name {settings['address']};
        location ^~ /.well-known/acme-challenge/ {{
            root {WEBROOT};
            default_type text/plain;
            try_files $uri =404;
        }}
        location / {{ return 404; }}
    }}
{https}}}
'''


def certbot_common() -> list[str]:
    return [str(OPT / 'certbot/bin/certbot'), '--config-dir', str(ACME / 'config'),
            '--work-dir', str(ACME / 'work'), '--logs-dir', str(ACME / 'logs')]


def certbot_command(settings: dict) -> list[str]:
    args = certbot_common() + ['certonly', '--non-interactive', '--agree-tos',
            '--webroot', '--webroot-path', str(WEBROOT), '--preferred-challenges', 'http',
            '--cert-name', CERT_NAME, '--reuse-key', '--key-type', 'ecdsa', '--keep-until-expiring']
    if settings['email']:
        args += ['--email', settings['email']]
    else:
        args += ['--register-unsafely-without-email']
    try:
        ipaddress.ip_address(settings['address'])
    except ValueError:
        args += ['--domains', settings['address']]
    else:
        args += ['--ip-address', settings['address'], '--required-profile', 'shortlived']
    return args


def hardening(user: str) -> str:
    return f'''User={user}
Group={user}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077
LimitNOFILE=65536
'''


def service_units() -> dict[str, str]:
    def service(description, body, *, after='network-online.target', user=None):
        return f'''# {MARKER}
[Unit]
Description={description}
After={after}
Wants=network-online.target
[Service]
''' + (hardening(user) if user else '') + body + '\n[Install]\nWantedBy=multi-user.target\n'
    units = {
        'vpsproxy-hy2.service': service('VPS proxy Hysteria 2',
            f'ExecStart={OPT}/bin/hysteria server --config {ETC}/hysteria.json --log-level warn\n'
            'SupplementaryGroups=vpsproxy-tls\nRestart=on-failure\nRestartSec=5\nCapabilityBoundingSet=\n', user='vpsproxy-hy2'),
        'vpsproxy-xray.service': service('VPS proxy Trojan',
            f'ExecStart={OPT}/bin/xray run -config {ETC}/xray.json\n'
            'SupplementaryGroups=vpsproxy-tls\nRestart=on-failure\nRestartSec=5\nCapabilityBoundingSet=\n', user='vpsproxy-xray'),
        'vpsproxy-sub.service': service('VPS proxy private subscriptions',
            f'WorkingDirectory={APP}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
            f'ExecStart=/usr/bin/python3 -m server.subscription.http_server --config {ETC}/subscription.json --data-dir {DATA} --port 18081\n'
            'Restart=on-failure\nRestartSec=5\nCapabilityBoundingSet=\n', user='vpsproxy-sub'),
        'vpsproxy-nginx.service': service('VPS proxy ACME and HTTPS',
            f'ExecStartPre=/usr/sbin/nginx -t -c {ETC}/nginx.conf\n'
            f'ExecStart=/usr/sbin/nginx -c {ETC}/nginx.conf -g "daemon off;"\n'
            'ExecReload=/bin/kill -HUP $MAINPID\n'
            'SupplementaryGroups=vpsproxy-tls\nRuntimeDirectory=vpsproxy-nginx\nRuntimeDirectoryMode=0700\n'
            'ReadWritePaths=/run/vpsproxy-nginx\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
            'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nRestart=on-failure\nRestartSec=5\n', user='vpsproxy-web'),
        'vpsproxy-refresh.service': service('Refresh VPS proxy routing profiles',
            f'Type=oneshot\nWorkingDirectory={APP}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n'
            f'ExecStart=/usr/bin/python3 -m server.subscription.refresh --settings {ETC}/settings.json --data-dir {DATA}\n'
            f'UMask=0027\nProtectSystem=strict\nReadWritePaths={DATA}\nProtectHome=true\nPrivateTmp=true\n'),
        'vpsproxy-renew.service': service('Renew VPS proxy TLS certificate',
            f'Type=oneshot\nWorkingDirectory={APP}\n'
            'ExecStart=' + ' '.join(certbot_common()) +
            f' renew --cert-name {CERT_NAME} --quiet --reuse-key --deploy-hook "/usr/bin/python3 {APP}/server/installer.py --deploy-certificate"\n'
            'UMask=0077\nPrivateTmp=true\nProtectHome=true\n')}
    for name, calendar in (('refresh', '*-*-* 04:15:00'), ('renew', '*-*-* 00,06,12,18:00:00')):
        units[f'vpsproxy-{name}.timer'] = f'''# {MARKER}
[Unit]
Description=Schedule VPS proxy {name}
[Timer]
OnCalendar={calendar}
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
'''
    return units


def write_units() -> None:
    for name, content in service_units().items():
        atomic_write(UNITS / name, content, 0o644)
    run(['systemctl', 'daemon-reload'])


def deploy_certificate(settings: dict, *, reload_nginx: bool = True) -> None:
    lineage = ACME / 'config/live' / CERT_NAME
    fullchain, private = lineage / 'fullchain.pem', lineage / 'privkey.pem'
    if not fullchain.is_file() or not private.is_file():
        raise InstallError('Certificate issuance did not produce the expected files.')
    run(['openssl', 'x509', '-in', str(fullchain), '-noout', '-checkend', '3600'])
    check_name = '-checkip' if re.fullmatch(r'[0-9.]+', settings['address']) else '-checkhost'
    run(['openssl', 'x509', '-in', str(fullchain), '-noout', check_name, settings['address']])
    public_cert = run(['openssl', 'x509', '-in', str(fullchain), '-noout', '-pubkey']).stdout.strip()
    public_key = run(['openssl', 'pkey', '-in', str(private), '-pubout']).stdout.strip()
    if not secrets.compare_digest(public_cert, public_key):
        raise InstallError('Renewed certificate and private key do not match.')
    current_key = ETC / 'tls/current/privkey.pem'
    if current_key.is_file():
        previous_public = run(['openssl', 'pkey', '-in', str(current_key), '-pubout']).stdout.strip()
        if not secrets.compare_digest(previous_public, public_key):
            raise InstallError('Renewal changed the private key; refusing a non-atomic key rotation. Restore the reusable key before renewal.')
    run(['openssl', 'verify', '-purpose', 'sslserver', '-CAfile', '/etc/ssl/certs/ca-certificates.crt',
         '-untrusted', str(fullchain), str(lineage / 'cert.pem')])
    tls_dir = ETC / 'tls'
    ensure_dir(tls_dir, 0o750, 'vpsproxy-tls')
    digest = hashlib.sha256(fullchain.read_bytes()).hexdigest()[:24]
    release = tls_dir / ('cert-' + digest)
    ensure_dir(release, 0o750, 'vpsproxy-tls')
    atomic_write(release / 'fullchain.pem', fullchain.read_bytes(), 0o640, 'vpsproxy-tls')
    atomic_write(release / 'privkey.pem', private.read_bytes(), 0o640, 'vpsproxy-tls')
    current = tls_dir / 'current'
    previous = os.readlink(current) if current.is_symlink() else None
    temporary = tls_dir / ('.current-' + secrets.token_hex(6))
    try:
        temporary.symlink_to(release.name, target_is_directory=True)
        os.replace(temporary, current)
        if reload_nginx and run(['systemctl', 'is-active', '--quiet', 'vpsproxy-nginx.service'], check=False).returncode == 0:
            run(['/usr/sbin/nginx', '-t', '-c', str(ETC / 'nginx.conf')])
            run(['systemctl', 'reload', 'vpsproxy-nginx.service'])
    except Exception:
        if previous is not None:
            temporary.unlink(missing_ok=True)
            temporary.symlink_to(previous, target_is_directory=True)
            os.replace(temporary, current)
        raise
    finally:
        temporary.unlink(missing_ok=True)
    # Hysteria reads each handshake; Xray's oneTimeLoading=false rereads every
    # hour. Reusing the key makes the tiny cross-file read window safe during a
    # swap. Renewal begins well before expiry, so no transport restart is needed.


def validate_transports() -> None:
    run(['runuser', '-u', 'vpsproxy-xray', '--', str(OPT / 'bin/xray'),
         'run', '-test', '-config', str(ETC / 'xray.json')])
    # Hysteria 2.12.3 has no config-check command. Run the actual config with
    # only the listener changed to an ephemeral loopback port, then stop it.
    probe = read_json(ETC / 'hysteria.json')
    probe['listen'] = '127.0.0.1:0'
    target = ETC / 'hysteria-check.json'
    atomic_write(target, json_text(probe), 0o640, 'vpsproxy-hy2')
    process = None
    try:
        process = subprocess.Popen(['runuser', '-u', 'vpsproxy-hy2', '--', str(OPT / 'bin/hysteria'),
                                    'server', '--config', str(target), '--log-level', 'info'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise InstallError('Hysteria rejected the generated configuration.')
        import signal
        os.killpg(process.pid, signal.SIGTERM)
        output, error = process.communicate(timeout=5)
        if 'server up and running' not in output + error:
            raise InstallError('Hysteria configuration startup could not be verified.')
    finally:
        if process is not None and process.poll() is None:
            import signal
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        target.unlink(missing_ok=True)


def tune_kernel() -> None:
    # Optional and conservative: don't change arbitrary limits or swap policy.
    if not shutil.which('sysctl'):
        return
    if shutil.which('modprobe'):
        run(['modprobe', 'tcp_bbr'], check=False)
    available = run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'], check=False)
    if 'bbr' not in available.stdout.split():
        return
    text = '# ' + MARKER + '\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n'
    target = Path('/etc/sysctl.d/90-vpsproxy.conf')
    if target.exists() and MARKER not in target.read_text():
        raise InstallError('An unmanaged tuning file occupies the reserved filename.')
    atomic_write(target, text, 0o644)
    run(['sysctl', '-p', str(target)])


def setup_tailscale(distro: tuple[str, str, str]) -> dict:
    family, _, codename = distro
    key_path = TAILSCALE_KEY
    source_path = TAILSCALE_SOURCE
    owner_path = ETC / 'tailscale-owned'
    source_text = f'# {MARKER}\ndeb [signed-by={key_path}] https://pkgs.tailscale.com/stable/{family} {codename} main\n'
    key_url = f'https://pkgs.tailscale.com/stable/{family}/{codename}.noarmor.gpg'
    if not owner_path.exists():
        if key_path.exists() or source_path.exists():
            raise InstallError('A reserved Tailscale repository file already exists.')
        key = download(key_url, max_bytes=100_000)
        owner = {'managed_by': MARKER, 'source': source_text, 'key_sha256': hashlib.sha256(key).hexdigest()}
        # Persist verifiable ownership BEFORE either external file. Every
        # interrupted point can then be retried without taking over unknown files.
        atomic_write(owner_path, json_text(owner))
    else:
        owner = read_json(owner_path)
        if owner.get('managed_by') != MARKER or owner.get('source') != source_text:
            raise InstallError('Tailscale repository ownership does not match this installation.')
        key = key_path.read_bytes() if key_path.exists() else download(key_url, max_bytes=100_000)
    if hashlib.sha256(key).hexdigest() != owner.get('key_sha256'):
        raise InstallError('The Tailscale repository key changed; refusing to replace an unknown key.')
    if source_path.exists() and source_path.read_text() != source_text:
        raise InstallError('The Tailscale repository file changed; refusing to replace it.')
    if not key_path.exists():
        atomic_write(key_path, key, 0o644)
    if not source_path.exists():
        atomic_write(source_path, source_text, 0o644)
    run(['apt-get', 'update'], timeout=900)
    run(['apt-get', 'install', '-y', '--no-install-recommends', 'tailscale'], timeout=900,
        env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'})
    run(['systemctl', 'enable', '--now', 'tailscaled.service'])
    state = run(['tailscale', 'status', '--json'], check=False)
    try:
        status = json.loads(state.stdout)
    except ValueError:
        status = {}
    if status.get('BackendState') == 'Running':
        return {'tailscale_status': 'connected'}
    # No auth key is accepted or stored. Bound the wait for human approval.
    result = run(['tailscale', 'up', '--timeout=10s', '--accept-dns=false', '--accept-routes=false'], check=False, timeout=30)
    try:
        if json.loads(run(['tailscale', 'status', '--json'], check=False).stdout).get('BackendState') == 'Running':
            return {'tailscale_status': 'connected'}
    except ValueError:
        pass
    match = re.search(r'https://login\.tailscale\.com/[A-Za-z0-9/_?=&.%+-]+', result.stdout + '\n' + result.stderr)
    answer = {'tailscale_status': 'authorization_required'}
    if match:
        answer['tailscale_auth_url'] = match.group(0)
    else:
        answer['tailscale_status'] = 'run_tailscale_up_on_server'
    return answer


def check_health(settings: dict) -> None:
    # Check trusted HTTPS through loopback while retaining address/SNI validation.
    import http.client
    import ssl
    context = ssl.create_default_context()
    for attempt in range(15):
        active = all(run(['systemctl', 'is-active', '--quiet', 'vpsproxy-' + name + '.service'], check=False).returncode == 0
                     for name in ('nginx', 'hy2', 'xray', 'sub'))
        listing = run(['ss', '-H', '-lntup']).stdout
        seen = set()
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] in ('tcp', 'udp'):
                try:
                    seen.add((fields[0], int(fields[4].rsplit(':', 1)[-1])))
                except ValueError:
                    pass
        listeners_ready = set(expected_listeners(settings)) <= seen
        if active and listeners_ready:
            check_listeners(settings, listing, managed=True)
            connection = http.client.HTTPSConnection(settings['address'], settings['ports']['https'], timeout=5, context=context)
            connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
                ('127.0.0.1', settings['ports']['https']), timeout)
            try:
                connection.request('GET', '/s/' + settings['token'] + '/clash.yaml')
                response = connection.getresponse()
                if response.status == 200 and response.read(1024):
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
        if attempt != 14:
            time.sleep(1)
    raise InstallError('Local service/listener/trusted HTTPS health check failed.')


def initialize_state(settings: dict) -> None:
    if ETC.exists():
        atomic_write(ETC / 'settings.json', json_text(settings))
        return
    # Stage the private settings and marker together so interruption can never
    # leave a half-owned final directory that a rerun must refuse.
    stage = Path(tempfile.mkdtemp(prefix='.vpsproxy-setup-', dir=ETC.parent))
    try:
        atomic_write(stage / 'settings.json', json_text(settings))
        atomic_write(stage / 'managed-by', MARKER + '\n')
        stage.chmod(0o755)
        os.rename(stage, ETC)
    finally:
        if stage.exists():
            for name in ('settings.json', 'managed-by'):
                (stage / name).unlink(missing_ok=True)
            stage.rmdir()


def install(config: dict) -> dict:
    cfg = validate_config(config)
    print('Checking operating system, ownership and listening ports...', flush=True)
    managed, distro = preflight(cfg)
    existing = read_json(ETC / 'settings.json') if (ETC / 'settings.json').exists() else None
    if managed and existing is None:
        raise InstallError('Managed installation has no settings; refusing to regenerate credentials.')
    settings = build_settings(cfg, existing)
    blocked_host_ips = host_addresses(settings)
    # Fail an incomplete payload before creating persistent state or installing.
    source = Path(__file__).resolve().parent
    for relative in ('subscription/refresh.py', 'subscription/http_server.py'):
        if not (source / relative).is_file():
            raise InstallError('Payload is missing subscription modules.')
    initialize_state(settings)
    ensure_dir(OPT)
    # Explicitly replace a prior success result so an interrupted rerun cannot
    # accidentally report stale success to the local wizard.
    result = {'schema_version': 1, 'status': 'installing',
              'base_url': settings['base_url'], 'clash_url': settings['base_url'] + '/clash.yaml',
              'shadowrocket_url': settings['base_url'] + '/shadowrocket.conf'}
    atomic_write(ETC / 'result.json', json_text(result))
    try:
        print('Installing system dependencies and isolated Certbot...', flush=True)
        install_dependencies()
        create_accounts()
        print('Downloading and verifying pinned transport binaries...', flush=True)
        install_binaries()
        copy_application()
        ensure_dir(DATA, 0o750, 'vpsproxy-sub')
        ensure_dir(WEBROOT, 0o755)
        ensure_dir(ACME, 0o700)
        for name in ('config', 'work', 'logs'):
            ensure_dir(ACME / name, 0o700)
        atomic_write(ETC / 'subscription.json', json_text({'token': settings['token']}), 0o640, 'vpsproxy-sub')
        for filename, content in transport_configs(settings, blocked_host_ips).items():
            group = 'vpsproxy-hy2' if filename.startswith('hysteria') else 'vpsproxy-xray'
            atomic_write(ETC / filename, json_text(content), 0o640, group)
        # Preserve HTTPS availability during reruns once a trusted cert exists.
        has_certificate = (ETC / 'tls/current/fullchain.pem').is_file()
        atomic_write(ETC / 'nginx.conf', nginx_config(settings, tls=has_certificate), 0o644)
        write_units()
        run(['systemctl', 'enable', '--now', 'vpsproxy-nginx.service'])
        run(['systemctl', 'reload', 'vpsproxy-nginx.service'])
        print('Obtaining or renewing the trusted HTTPS certificate via TCP 80...', flush=True)
        run(certbot_command(settings), timeout=600)
        deploy_certificate(settings)
        validate_transports()
        atomic_write(ETC / 'nginx.conf', nginx_config(settings, tls=True), 0o644)
        run(['/usr/sbin/nginx', '-t', '-c', str(ETC / 'nginx.conf')])
        print('Validating transport configurations and refreshing routing profiles...', flush=True)
        run(['systemctl', 'start', 'vpsproxy-refresh.service'], timeout=300)
        run(['systemctl', 'enable', '--now', 'vpsproxy-hy2.service', 'vpsproxy-xray.service', 'vpsproxy-sub.service'])
        # Restart only our transports/subscription app after their config/code changed.
        run(['systemctl', 'restart', 'vpsproxy-hy2.service', 'vpsproxy-xray.service', 'vpsproxy-sub.service'])
        run(['systemctl', 'reload', 'vpsproxy-nginx.service'])
        run(['systemctl', 'enable', '--now', 'vpsproxy-refresh.timer', 'vpsproxy-renew.timer'])
        if cfg['tune']:
            tune_kernel()
        if cfg['tailscale']:
            print('Installing Tailscale and preparing interactive authorization...', flush=True)
            result.update(setup_tailscale(distro))
        print('Checking local services and trusted HTTPS...', flush=True)
        check_health(settings)
        result['status'] = 'ready'
        atomic_write(ETC / 'result.json', json_text(result))
        return result
    except Exception:
        result['status'] = 'failed'
        atomic_write(ETC / 'result.json', json_text(result))
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--deploy-certificate', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.deploy_certificate:
            if args.plan or args.config is not None:
                raise InstallError('Certificate deployment cannot be combined with other modes.')
            if sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0:
                raise InstallError('Certificate deployment requires root on Linux.')
            with install_lock():
                deploy_certificate(read_json(ETC / 'settings.json'))
            return 0
        if args.config is None:
            parser.error('--config is required')
        config = validate_config(read_json(args.config))
        if args.plan:
            print(json_text(plan(config)), end='')
            return 0
        # Lock only after checking root, leaving --plan entirely effect-free.
        if sys.platform != 'linux' or getattr(os, 'geteuid', lambda: -1)() != 0:
            raise InstallError('Installation requires root on Linux; use --plan for a local preview.')
        with install_lock():
            install(config)
        print('Installation ready. Import URLs are in /etc/vps-proxy-setup/result.json (root only).')
        return 0
    except InstallError as error:
        print('Error: ' + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Error: installation failed; inspect private server logs. No credentials were printed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
