"""Server safety/configuration tests. No root commands or internet are used."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest import mock

from vps_proxy_setup.server import installer as inst


def configuration():
    return {'schema_version': 1, 'label': 'Sample', 'address': 'proxy.example.net',
            'tls_name': 'proxy.example.net', 'email': '', 'acme_accept_terms': True,
            'ports': {'https': 8443, 'hy2': 8443, 'trojan': 9443},
            'tailscale': False, 'tune': False}


def completed(args=(), code=0, stdout=''):
    return subprocess.CompletedProcess(args, code, stdout, '')


class ConfigurationTests(unittest.TestCase):
    def test_valid_normalized_configuration(self):
        cfg = configuration()
        cfg['address'] = cfg['tls_name'] = 'Proxy.Example.NET'
        self.assertEqual(inst.validate_config(cfg)['address'], 'proxy.example.net')

    def test_reject_bad_values_without_reflecting_them(self):
        invalid = [None, [], {}, {**configuration(), 'unknown': 'value'},
                   {**configuration(), 'schema_version': True},
                   {**configuration(), 'label': 'bad label'},
                   {**configuration(), 'tls_name': None},
                   {**configuration(), 'tls_name': 'elsewhere.example.net'},
                   {**configuration(), 'acme_accept_terms': False},
                   {**configuration(), 'email': 'bad\nemail'},
                   {**configuration(), 'tailscale': 'yes'}]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(inst.InstallError):
                inst.validate_config(value)

    def test_reject_nonpublic_ipv4_ipv6_and_injection(self):
        for address in ('127.0.0.1', '10.1.2.3', '203.0.113.7', '::1',
                        '2001:db8::1', 'example.net; touch /tmp/bad',
                        'example.net\n', 'example.net.', '-x.example.net', 'localhost',
                        '1.2.3.999', 'https://example.net'):
            cfg = configuration()
            cfg['address'] = cfg['tls_name'] = address
            with self.subTest(address=address), self.assertRaises(inst.InstallError):
                inst.validate_config(cfg)

    def test_port_validation_and_udp_tcp_sharing(self):
        self.assertEqual(inst.validate_config(configuration())['ports']['hy2'], 8443)
        for port in (True, '8443', 80, 18081, 65536, -1):
            cfg = configuration()
            cfg['ports']['hy2'] = port
            with self.subTest(port=port), self.assertRaises(inst.InstallError):
                inst.validate_config(cfg)
        cfg = configuration()
        cfg['ports']['trojan'] = cfg['ports']['https']
        with self.assertRaises(inst.InstallError):
            inst.validate_config(cfg)

    def test_new_settings_and_stable_rerun(self):
        cfg = configuration()
        first = inst.build_settings(cfg)
        other = inst.build_settings(cfg)
        self.assertNotEqual(first['token'], other['token'])
        self.assertEqual(first['hy2_port'], cfg['ports']['hy2'])
        cfg['label'] = 'Updated'
        second = inst.build_settings(cfg, first)
        for key in ('clients', 'hy2_obfs', 'token', 'base_url'):
            self.assertEqual(first[key], second[key])
        self.assertEqual(second['label'], 'Updated')
        for name in ('windows', 'iphone'):
            self.assertTrue(first['clients'][name]['hy2_auth'].startswith(name + ':'))
        self.assertNotEqual(first['clients']['windows']['trojan_password'], first['clients']['iphone']['trojan_password'])

    def test_rerun_rejects_endpoint_changes(self):
        cfg = configuration()
        old = inst.build_settings(cfg)
        cfg['ports']['https'] += 1
        with self.assertRaises(inst.InstallError):
            inst.build_settings(cfg, old)

    def test_rerun_never_repairs_bad_secret_state_by_rotation(self):
        first = inst.build_settings(configuration())
        for field in ('clients', 'token', 'hy2_obfs'):
            broken = copy.deepcopy(first)
            broken[field] = None
            with self.subTest(field=field), mock.patch.object(inst.secrets, 'token_urlsafe') as generate:
                with self.assertRaises(inst.InstallError):
                    inst.build_settings(configuration(), broken)
                generate.assert_not_called()

    def test_plan_has_no_effects_or_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'input.json'
            source.write_text(json.dumps(configuration()), encoding='utf-8')
            with mock.patch.object(inst, 'run') as command, mock.patch.object(inst, 'download') as network, \
                    mock.patch.object(inst, 'atomic_write') as write, mock.patch.object(inst, 'install_lock') as lock, \
                    mock.patch.object(inst.secrets, 'token_urlsafe') as secret, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(inst.main(['--config', str(source), '--plan']), 0)
            for function in (command, network, write, lock, secret):
                function.assert_not_called()
            result = json.loads(output.getvalue())
            self.assertEqual(result['mode'], 'plan')
            self.assertEqual(result['required_tcp_ports'], [80, 8443, 9443])
            self.assertNotIn('token', result)
            self.assertNotIn('clients', result)


class GeneratedConfigTests(unittest.TestCase):
    def setUp(self):
        self.settings = inst.build_settings(configuration())

    def test_transport_auth_and_certificate_reload(self):
        cfg = inst.transport_configs(self.settings)
        hy2, xray = cfg['hysteria.json'], cfg['xray.json']
        self.assertEqual(hy2['listen'], '0.0.0.0:8443')
        for name, value in self.settings['clients'].items():
            self.assertEqual(hy2['auth']['userpass'][name], value['hy2_auth'].split(':', 1)[1])
        trojan = xray['inbounds'][0]
        self.assertEqual(trojan['protocol'], 'trojan')
        self.assertEqual(trojan['port'], 9443)
        tls = trojan['streamSettings']['tlsSettings']
        self.assertFalse(tls['certificates'][0]['oneTimeLoading'])
        self.assertEqual(tls['minVersion'], '1.2')
        self.assertNotIn('allowInsecure', tls)
        self.assertEqual(tls['certificates'][0]['keyFile'], hy2['tls']['key'])
        self.assertEqual(xray['log']['access'], 'none')

    def test_egress_blocks_private_metadata_and_server_addresses(self):
        cfg = inst.transport_configs(self.settings, ['203.0.113.8', '2001:db8::8'])
        hy2, xray = cfg['hysteria.json'], cfg['xray.json']
        for value in ('169.254.0.0/16', '100.64.0.0/10', 'fc00::/7', '203.0.113.8/32', '2001:db8::8/128'):
            self.assertIn('reject(' + value + ')', hy2['acl']['inline'])
            self.assertIn(value, xray['routing']['rules'][0]['ip'])
        self.assertEqual(hy2['acl']['inline'][-1], 'direct(all)')
        self.assertEqual(hy2['outbounds'][0]['direct']['mode'], '46')
        self.assertEqual(xray['routing']['domainStrategy'], 'IPIfNonMatch')
        self.assertEqual(xray['outbounds'][1]['protocol'], 'blackhole')
        self.assertEqual(xray['inbounds'][0]['streamSettings']['sockopt'],
                         {'tcpKeepAliveIdle': 30, 'tcpKeepAliveInterval': 15})

    def test_nginx_bootstrap_and_tls_both_disable_url_logging(self):
        bootstrap = inst.nginx_config(self.settings, tls=False)
        configured = inst.nginx_config(self.settings, tls=True)
        for text in (bootstrap, configured):
            self.assertIn('access_log off;', text)
            self.assertIn('error_log /dev/null crit;', text)
            self.assertIn('listen 0.0.0.0:80;', text)
            self.assertIn('/.well-known/acme-challenge/', text)
            self.assertNotIn(self.settings['token'], text)
        self.assertNotIn('ssl_certificate ', bootstrap)
        self.assertIn('listen 0.0.0.0:8443 ssl;', configured)
        self.assertIn('proxy_pass http://127.0.0.1:18081;', configured)
        self.assertIn('gzip on;', configured)
        self.assertIn('gzip_types application/yaml application/json text/plain;', configured)
        self.assertNotIn('sites-enabled', configured)

    def test_certbot_dns_and_ip_paths_use_reusable_keys(self):
        dns = inst.certbot_command(self.settings)
        self.assertIn('--domains', dns)
        self.assertIn('--reuse-key', dns)
        self.assertIn('--keep-until-expiring', dns)
        # This branch test uses a documentation-only IPv4, bypassing validation;
        # production validate_config rejects this reserved address.
        data = dict(self.settings, address='203.0.113.7')
        ip = inst.certbot_command(data)
        self.assertIn('--ip-address', ip)
        self.assertEqual(ip[ip.index('--required-profile') + 1], 'shortlived')
        self.assertNotIn('--domains', ip)
        self.assertNotIn('--standalone', ip)

    def test_service_accounts_hardening_and_timers(self):
        units = inst.service_units()
        for name, user in (('hy2', 'hy2'), ('xray', 'xray'), ('sub', 'sub'), ('nginx', 'web')):
            unit = units['vpsproxy-' + name + '.service']
            self.assertIn('User=vpsproxy-' + user, unit)
            self.assertIn('NoNewPrivileges=true', unit)
            self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('--port 18081', units['vpsproxy-sub.service'])
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', units['vpsproxy-nginx.service'])
        self.assertIn('00,06,12,18:00:00', units['vpsproxy-renew.timer'])
        self.assertIn('--reuse-key', units['vpsproxy-renew.service'])
        self.assertIn('--deploy-certificate', units['vpsproxy-renew.service'])
        self.assertIn('Persistent=true', units['vpsproxy-refresh.timer'])

    def test_binary_manifest_is_pinned_for_both_architectures(self):
        assets = inst.read_json(Path(inst.__file__).with_name('assets.json'))
        self.assertEqual(assets['hysteria']['version'], '2.12.3')
        self.assertEqual(assets['xray']['version'], '26.3.27')
        for product in ('hysteria', 'xray'):
            for arch in ('amd64', 'arm64'):
                self.assertRegex(assets[product][arch]['sha256'], r'^[0-9a-f]{64}$')
                self.assertTrue(assets[product][arch]['url'].startswith('https://github.com/'))


class ListeningPortTests(unittest.TestCase):
    @staticmethod
    def line(proto='tcp', port=80, pid='45'):
        return f'{proto} LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("service",pid={pid},fd=3))'

    def test_unmanaged_required_ports_fail_including_acme(self):
        for proto, port in inst.expected_listeners(configuration()):
            with self.subTest(proto=proto, port=port), self.assertRaises(inst.InstallError):
                inst.check_listeners(configuration(), self.line(proto, port), managed=False)

    def test_unrelated_ports_are_not_modified(self):
        inst.check_listeners(configuration(), self.line(port=22), managed=False)

    def test_only_exact_systemd_owner_is_allowed_on_rerun(self):
        reader = lambda pid: '0::/system.slice/vpsproxy-nginx.service\n'
        inst.check_listeners(configuration(), self.line(), managed=True, cgroup_reader=reader)
        for bad in ('0::/system.slice/nginx.service\n', '0::/system.slice/vpsproxy-nginx.service-other\n'):
            with self.assertRaises(inst.InstallError):
                inst.check_listeners(configuration(), self.line(), managed=True, cgroup_reader=lambda pid: bad)

    def test_missing_pid_or_ambiguous_owners_fail_closed(self):
        with self.assertRaises(inst.InstallError):
            inst.check_listeners(configuration(), 'tcp LISTEN 0 128 [::]:80 [::]:*', managed=True)
        listing = self.line() + ',("other",pid=46,fd=5)'
        with self.assertRaises(inst.InstallError):
            inst.check_listeners(configuration(), listing, managed=True,
                cgroup_reader=lambda pid: '/vpsproxy-nginx.service' if pid == '45' else '/other.service')


class MutationBoundaryTests(unittest.TestCase):
    def test_command_failure_does_not_disclose_output_or_arguments(self):
        private = secrets.token_urlsafe(32)
        result = subprocess.CompletedProcess([], 1, private, private)
        with mock.patch.object(inst.subprocess, 'run', return_value=result):
            with self.assertRaises(inst.InstallError) as caught:
                inst.run(['tool', private])
        self.assertNotIn(private, str(caught.exception))

    def test_download_hash_mismatch_and_http_rejected(self):
        content = b'public synthetic binary bytes'
        opener = mock.Mock()
        opener.open.return_value = io.BytesIO(content)
        with mock.patch.object(inst.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(inst.InstallError):
                inst.download('https://example.net/asset', sha256='0' * 64)
        opener.open.return_value = io.BytesIO(content)
        with mock.patch.object(inst.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(inst.download('https://example.net/asset', sha256=hashlib.sha256(content).hexdigest()), content)
        with self.assertRaises(inst.InstallError):
            inst.download('http://example.net/asset')

    def test_atomic_write_preserves_previous_file_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'value.json'
            target.write_text('previous', encoding='utf-8')
            with mock.patch.object(inst.os, 'replace', side_effect=OSError('simulated')):
                with self.assertRaises(OSError):
                    inst.atomic_write(target, 'new')
            self.assertEqual(target.read_text(), 'previous')
            self.assertEqual(list(Path(temp).iterdir()), [target])

    def test_initial_state_becomes_visible_as_a_complete_owned_directory(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(inst, 'ETC', Path(temp) / 'etc'):
            settings = inst.build_settings(configuration())
            original_rename = inst.os.rename
            def inspect_stage(source, destination):
                self.assertFalse(inst.ETC.exists())
                self.assertEqual(inst.read_json(source / 'settings.json'), settings)
                self.assertEqual((source / 'managed-by').read_text(), inst.MARKER + '\n')
                original_rename(source, destination)
            with mock.patch.object(inst.os, 'rename', side_effect=inspect_stage):
                inst.initialize_state(settings)
            self.assertEqual(inst.read_json(inst.ETC / 'settings.json'), settings)
            self.assertEqual(list(Path(temp).iterdir()), [inst.ETC])

    def test_certificate_key_rotation_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            base = Path(temp)
            stack.enter_context(mock.patch.object(inst, 'ETC', base / 'etc'))
            stack.enter_context(mock.patch.object(inst, 'ACME', base / 'acme'))
            lineage = inst.ACME / 'config/live' / inst.CERT_NAME
            lineage.mkdir(parents=True)
            (lineage / 'fullchain.pem').write_text('synthetic certificate')
            (lineage / 'privkey.pem').write_text('synthetic new key')
            current = inst.ETC / 'tls/current'
            current.mkdir(parents=True)
            (current / 'privkey.pem').write_text('synthetic previous key')
            def command(args, **kwargs):
                if '-pubout' in args or '-pubkey' in args:
                    return completed(args, stdout='old public key' if str(current / 'privkey.pem') in args else 'new public key')
                return completed(args)
            stack.enter_context(mock.patch.object(inst, 'run', side_effect=command))
            write = stack.enter_context(mock.patch.object(inst, 'atomic_write'))
            with self.assertRaisesRegex(inst.InstallError, 'changed the private key'):
                inst.deploy_certificate(inst.build_settings(configuration()))
            write.assert_not_called()
            self.assertEqual((current / 'privkey.pem').read_text(), 'synthetic previous key')

    def test_interrupted_tailscale_repository_setup_is_retryable(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            base = Path(temp)
            stack.enter_context(mock.patch.object(inst, 'ETC', base / 'etc'))
            inst.ETC.mkdir()
            stack.enter_context(mock.patch.object(inst, 'TAILSCALE_KEY', base / 'tailscale.gpg'))
            stack.enter_context(mock.patch.object(inst, 'TAILSCALE_SOURCE', base / 'tailscale.list'))
            stack.enter_context(mock.patch.object(inst, 'download', return_value=b'synthetic public repository key'))
            stack.enter_context(mock.patch.object(inst, 'run', side_effect=lambda args, **kw: completed(args, stdout='{"BackendState":"Running"}')))
            original_write = inst.atomic_write
            def interrupted(path, *args, **kwargs):
                if path == inst.TAILSCALE_KEY:
                    raise OSError('simulated power loss before repository files')
                return original_write(path, *args, **kwargs)
            with mock.patch.object(inst, 'atomic_write', side_effect=interrupted), self.assertRaises(OSError):
                inst.setup_tailscale(('debian', '12', 'bookworm'))
            self.assertTrue((inst.ETC / 'tailscale-owned').is_file())
            self.assertFalse(inst.TAILSCALE_KEY.exists())
            self.assertEqual(inst.setup_tailscale(('debian', '12', 'bookworm'))['tailscale_status'], 'connected')
            self.assertTrue(inst.TAILSCALE_KEY.is_file())
            self.assertTrue(inst.TAILSCALE_SOURCE.is_file())
            inst.TAILSCALE_SOURCE.write_text('unmanaged replacement')
            with self.assertRaisesRegex(inst.InstallError, 'repository file changed'):
                inst.setup_tailscale(('debian', '12', 'bookworm'))

    def test_unsupported_os_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'os-release'
            for os_id, version in (('debian', '11'), ('ubuntu', '20.04'), ('alpine', '3.20')):
                path.write_text(f'ID={os_id}\nVERSION_ID="{version}"\n')
                with self.assertRaises(inst.InstallError):
                    inst.os_release(path)
            path.write_text('ID=debian\nVERSION_ID="13"\n')
            self.assertEqual(inst.os_release(path), ('debian', '13', 'trixie'))

    def test_real_install_rejected_on_nonlinux_before_root_mutations(self):
        with mock.patch.object(inst.sys, 'platform', 'win32'), mock.patch.object(inst, 'run') as commands, \
                mock.patch.object(inst, 'atomic_write') as write:
            with self.assertRaises(inst.InstallError):
                inst.install(configuration())
        commands.assert_not_called()
        write.assert_not_called()

    def test_complete_flow_and_rerun_with_all_root_operations_mocked(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            root = Path(temp)
            for constant, relative in (('ETC', 'etc'), ('OPT', 'opt'), ('APP', 'opt/app'),
                                       ('DATA', 'data'), ('ACME', 'etc/acme'), ('WEBROOT', 'web'), ('UNITS', 'units')):
                stack.enter_context(mock.patch.object(inst, constant, root / relative))
            inst.UNITS.mkdir()
            stack.enter_context(mock.patch.object(inst.shutil, 'chown'))
            stack.enter_context(mock.patch.object(inst, 'preflight', return_value=(False, ('debian', '12', 'bookworm'))))
            stack.enter_context(mock.patch.object(inst, 'host_addresses', return_value=['203.0.113.8']))
            for operation in ('install_dependencies', 'create_accounts', 'install_binaries', 'copy_application',
                              'deploy_certificate', 'validate_transports', 'check_health'):
                stack.enter_context(mock.patch.object(inst, operation))
            commands = stack.enter_context(mock.patch.object(inst, 'run', side_effect=lambda args, **kw: completed(args)))
            result = inst.install(configuration())
            self.assertEqual(result['status'], 'ready')
            first = inst.read_json(inst.ETC / 'settings.json')
            self.assertEqual(inst.read_json(inst.ETC / 'subscription.json'), {'token': first['token']})
            self.assertTrue((inst.UNITS / 'vpsproxy-renew.timer').is_file())
            second_result = inst.install(configuration())
            second = inst.read_json(inst.ETC / 'settings.json')
            self.assertEqual(first['clients'], second['clients'])
            self.assertEqual(result, second_result)
            for call in commands.call_args_list:
                args = call.args[0]
                if args[:2] == ['systemctl', 'restart']:
                    self.assertTrue(all(name.startswith('vpsproxy-') for name in args[2:]))
            inst.check_health.side_effect = inst.InstallError('simulated health failure')
            with self.assertRaises(inst.InstallError):
                inst.install(configuration())
            self.assertEqual(inst.read_json(inst.ETC / 'result.json')['status'], 'failed')
            self.assertEqual(first['token'], inst.read_json(inst.ETC / 'settings.json')['token'])


if __name__ == '__main__':
    unittest.main()
