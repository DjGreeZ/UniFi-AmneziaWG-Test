#!/usr/bin/env python3
"""Bounded read-only AWG diagnostics. No VPN configs, keys or packet payloads."""
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path('/data/awg-native')
AWG = str(ROOT / 'bin/awg')
NS = ['ip', 'netns', 'exec', 'awgm']
DEADLINE = 0
LIMIT = 80000


def clean(value):
    value = value.decode('utf-8', 'replace') if isinstance(value, bytes) else value
    value = re.sub(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![=])', '[key omitted]', value)
    value = '\n'.join('[sensitive line omitted]' if re.search(
        r'private.?key|preshared.?key|headerprotectionkey|authorization:|cookie:|password\s*[=:]|token\s*[=:]',
        line, re.I) else line for line in value.splitlines())
    return value[:LIMIT] + ('\n[truncated]' if len(value) > LIMIT else '')


def run(args, timeout=6, transform=None):
    remaining = DEADLINE - time.monotonic() if DEADLINE else timeout
    if remaining <= 0:
        return {'code': None, 'error': 'diagnostic time limit reached'}
    started = time.monotonic()
    try:
        # Temporary files also bound RAM when a router has a large firewall.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(args, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                code = process.wait(timeout=min(timeout, remaining))
                timed_out = False
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                timed_out = True
            except BaseException:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                raise
            out.seek(0)
            err.seek(0)
            stdout = out.read(2 * 1024 * 1024).decode('utf-8', 'replace')
            stderr = err.read(LIMIT)
        if transform:
            stdout = transform(stdout)
        return {'code': code, 'timeout': timed_out, 'seconds': round(time.monotonic() - started, 2),
                'stdout': clean(stdout), 'stderr': clean(stderr)}
    except (OSError, ValueError) as exc:
        return {'code': None, 'error': clean(str(exc))}


def read_small(path):
    try:
        with open(path, 'rb') as stream:
            return clean(stream.read(4096)).replace('\x00', '')
    except OSError as exc:
        return clean(str(exc))


def strip_peers(text):
    return '\n'.join('peer%d %s' % (number, line.partition('\t')[2])
                     for number, line in enumerate(text.splitlines(), 1))


def awg_state(dev):
    result = {'unix_time': int(time.time())}
    for field in ('latest-handshakes', 'transfer', 'allowed-ips', 'endpoints'):
        result[field] = run([AWG, 'show', dev, field], transform=strip_peers)
    for field in ('fwmark', 'listen-port'):
        result[field] = run([AWG, 'show', dev, field])
    return result


def parse_endpoints(text):
    endpoints = []
    for line in text.splitlines():
        value = line.split()[-1] if line.split() else ''
        host, separator, port = value.rpartition(':')
        try:
            address = ipaddress.ip_address(host.strip('[]'))
            if separator and port.isdecimal() and 1 <= int(port) <= 65535:
                endpoints.append((str(address), int(port)))
        except ValueError:
            pass
    return endpoints[:4]


class Capture:
    def __init__(self, prefix, interface, expression):
        self.process = None
        self.output = None
        self.error = None
        if not shutil.which('tcpdump'):
            self.error = 'tcpdump unavailable; skipped without installing anything'
            return
        if DEADLINE and time.monotonic() >= DEADLINE:
            self.error = 'diagnostic time limit reached'
            return
        try:
            self.output = tempfile.TemporaryFile()
            self.process = subprocess.Popen(prefix + ['tcpdump', '-p', '-nn', '-tt', '-q', '-l',
                '-s', '80', '-c', '64', '-i', interface, expression],
                stdout=self.output, stderr=self.output, stdin=subprocess.DEVNULL, start_new_session=True)
        except OSError as exc:
            self.error = clean(str(exc))

    def finish(self):
        result = {'error': self.error} if self.error else {}
        try:
            if self.process:
                if self.process.poll() is None:
                    try:
                        os.killpg(self.process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.process.pid, signal.SIGKILL)
                        self.process.wait()
                result['code'] = self.process.returncode
            if self.output:
                self.output.seek(0)
                result['packet_summaries'] = clean(self.output.read(LIMIT))
        finally:
            if self.output:
                self.output.close()
                self.output = None
        return result


def curl_probe(prefix, interface, url):
    args = prefix + ['curl', '-q', '-4', '--noproxy', '*', '--retry', '0',
        '--connect-timeout', '4', '--max-time', '7', '--max-filesize', '65536',
        '--silent', '--show-error', '--verbose', '--output', '/dev/null',
        '--write-out', 'HTTP=%{http_code} local=%{local_ip} remote=%{remote_ip} '
        'connect=%{time_connect} tls=%{time_appconnect} total=%{time_total}\n']
    if interface:
        args += ['--interface', interface]
    return run(args + [url], timeout=9)


def connection(dev):
    result = {'interface': dev, 'before': awg_state(dev)}
    result['route_to_probe'] = run(NS + ['ip', 'route', 'get', '1.1.1.1', 'oif', dev])
    result['link_before'] = run(NS + ['ip', '-s', '-d', 'link', 'show', 'dev', dev])
    result['rp_filter'] = run(NS + ['sysctl', 'net.ipv4.conf.all.rp_filter',
        'net.ipv4.conf.default.rp_filter', 'net.ipv4.conf.' + dev + '.rp_filter',
        'net.ipv4.conf.all.src_valid_mark'])
    endpoints = parse_endpoints(result['before']['endpoints'].get('stdout', ''))
    mark = result['before']['fwmark'].get('stdout', '').strip()
    mark_args = ['mark', mark] if re.fullmatch(r'0x[0-9a-fA-F]+|[0-9]+', mark) else []
    result['outer_routes'] = [run(['ip', '-6' if ':' in host else '-4', 'route', 'get', host,
        'ipproto', 'udp', 'dport', str(port)] + mark_args) for host, port in endpoints]
    captures = {'inner': Capture(NS, dev,
        '(host 1.1.1.1 or host 1.0.0.1) and (icmp or (tcp and (port 80 or port 443)))')}
    if endpoints:
        expression = 'udp and (' + ' or '.join('(host %s and port %d)' % item for item in endpoints) + ')'
        captures['outer'] = Capture([], 'any', expression)
    try:
        # Let packet captures attach before generating the test connections.
        time.sleep(.3)
        result['ping'] = run(NS + ['ping', '-n', '-I', dev, '-c', '2', '-W', '1', '1.1.1.1'], timeout=4)
        result['https_primary'] = curl_probe(NS, dev, 'https://1.1.1.1/cdn-cgi/trace')
        result['http_primary'] = curl_probe(NS, dev, 'http://1.1.1.1/cdn-cgi/trace')
        result['https_alternate'] = curl_probe(NS, dev, 'https://1.0.0.1/cdn-cgi/trace')
        result['after'] = awg_state(dev)
        result['link_after'] = run(NS + ['ip', '-s', 'link', 'show', 'dev', dev])
    finally:
        result['captures'] = {name: capture.finish() for name, capture in captures.items()}
    return result


def matching(text):
    return '\n'.join(line for line in text.splitlines()
        if re.search(r'queue|zapret|nfqws|tpws', line, re.I)) or '(no matches)'


def collect(report):
    checks = {
        'kernel': ['uname', '-srm'],
        'network_version': ['dpkg-query', '-W', '-f=${Package} ${Version}\n', 'unifi-native', 'unifi'],
        'iptables_version': ['iptables', '--version'],
        'curl_version': ['curl', '--version'],
        'awg_version': [AWG, '--version'],
        'services': ['systemctl', 'show', 'awg-native.service', 'awg-native-panel.service',
            '-p', 'Id', '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'ExecMainStatus'],
        'root_rules': ['ip', '-4', 'rule', 'show'],
        'root_links': ['ip', '-brief', 'link'],
        'root_default_routes': ['ip', '-4', 'route', 'show', 'table', 'all', 'default'],
        'namespace_links': NS + ['ip', '-brief', 'address'],
        'namespace_rules': NS + ['ip', '-4', 'rule', 'show'],
        'namespace_routes': NS + ['ip', '-4', 'route', 'show', 'table', 'all'],
        'namespace_firewall': NS + ['iptables-save', '-c'],
        'namespace_queue_listeners': NS + ['cat', '/proc/net/netfilter/nfnetlink_queue'],
        'root_rp_filter': ['sysctl', 'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.default.rp_filter'],
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = {key: pool.submit(run, args) for key, args in checks.items()}
        report['checks'] = {key: future.result() for key, future in pending.items()}
    report['firmware'] = read_small('/usr/lib/version')
    report['model'] = read_small('/proc/device-tree/model')
    report['root_queue_listeners'] = read_small('/proc/net/netfilter/nfnetlink_queue')
    report['interference_checks'] = {
        'process_names': run(['ps', '-eo', 'pid,comm'], transform=matching),
        'unit_files': run(['systemctl', 'list-unit-files', '--no-pager'], transform=matching),
        'iptables': run(['iptables-save', '-c'], transform=matching),
    }
    if shutil.which('ip6tables-save'):
        report['interference_checks']['ip6tables'] = run(['ip6tables-save', '-c'], transform=matching)
    if shutil.which('nft'):
        report['interference_checks']['nftables'] = run(['nft', '-a', 'list', 'ruleset'], transform=matching)
        report['interference_checks']['namespace_nftables'] = run(NS + ['nft', '-a', 'list', 'ruleset'])
    report['curl_overrides'] = {
        'proxy_variable_names_only': sorted(key for key in os.environ if key.lower() in
            ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')),
        'root_curlrc_exists': Path('/root/.curlrc').exists(),
        'root_config_curlrc_exists': Path('/root/.config/curlrc').exists(),
    }
    report['component_hashes'] = {}
    for relative in ('service.py', 'config_parser.py', 'bin/amneziawg-go', 'bin/awg'):
        try:
            report['component_hashes'][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        except OSError:
            report['component_hashes'][relative] = 'unavailable'
    report['router_https_control'] = curl_probe([], None, 'https://1.1.1.1/cdn-cgi/trace')
    links = run(NS + ['ip', '-o', 'link', 'show'])
    report['interface_discovery'] = links
    interfaces = sorted(set(re.findall(r'^\d+: (awgo[1-4])(?:@[^:]+)?:', links.get('stdout', ''), re.M)))
    report['connections'] = []
    for dev in interfaces:
        print('  Проверка ' + dev + '…', flush=True)
        report['connections'].append(connection(dev))
    if not interfaces:
        report['note'] = 'No active awgo1..awgo4 interface; enable the affected connection and rerun.'


def main():
    global DEADLINE
    if os.geteuid() != 0 or not shutil.which('ip'):
        raise SystemExit('Запустите команду в SSH на роутере от root.')
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    os.umask(0o077)
    DEADLINE = time.monotonic() + 150
    report = {'diagnostic_version': 1, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'scope': 'Read-only system checks and bounded network probes; no VPN configuration files, '
                 'keys, passwords, environment values, journals or packet payloads collected. '
                 'The report contains IP addresses, routing and firewall information.'}
    descriptor, path = tempfile.mkstemp(prefix='awg-diagnostic-', suffix='.json', dir='/tmp')
    print('Диагностика AmneziaWG. Обычно 1–3 минуты. Настройки не изменяются.', flush=True)
    try:
        collect(report)
    except KeyboardInterrupt:
        report['interrupted'] = True
    except Exception as exc:
        report['error'] = clean(str(exc))
    finally:
        report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write('\n')
    print('Отчёт: ' + path, flush=True)


if __name__ == '__main__':
    main()
