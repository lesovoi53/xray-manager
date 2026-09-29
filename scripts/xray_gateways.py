"""Read panel table and template gateways through the same selection rules."""
import json


def kind(inbound):
    if inbound.get('listen') != '127.0.0.1':
        return None  # All installed routing helpers use IPv4 loopback.
    settings = inbound.get('settings') or {}
    protocol = inbound.get('protocol')
    if protocol in ('socks', 'mixed'):
        if settings.get('auth', 'noauth') == 'noauth' and settings.get('udp') is True:
            return 'SOCKS'
    elif protocol == 'dokodemo-door' and settings.get('followRedirect') is True:
        network = set(settings.get('network', 'tcp').split(','))
        transparent = (inbound.get('streamSettings') or {}).get('sockopt', {}).get('tproxy')
        if transparent == 'tproxy' and {'tcp', 'udp'} <= network:
            return 'TPROXY'
        if transparent != 'tproxy' and 'tcp' in network:
            return 'REDIRECT'
    return None


def panel_gateways(connection, preferred):
    rows = [dict(row) for row in connection.execute('SELECT * FROM inbounds')]
    row = connection.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
    template = json.loads(row[0]) if row else None
    candidates = list(template.get('inbounds', [])) if template else []
    for row in rows:
        if row['enable']:
            candidates.append(dict(protocol=row['protocol'], listen=row['listen'], port=row['port'],
                                   settings=json.loads(row['settings'] or '{}'),
                                   streamSettings=json.loads(row['stream_settings'] or '{}')))
    ports = {}
    for inbound in candidates:
        key = kind(inbound)
        if key:
            port = int(inbound['port'])
            if not 1 <= port <= 65535 or port in (443, 8443):
                raise ValueError('Forbidden gateway port for ' + key)
            ports.setdefault(key, set()).add(port)
    found = {}
    for key, choices in ports.items():
        saved = preferred.get('XRAY_' + key + '_PORT')
        if saved is not None:
            if int(saved) not in choices:
                raise ValueError('Saved ' + key + ' gateway conflicts with panel configuration')
            found[key] = int(saved)
        elif len(choices) == 1:
            found[key] = next(iter(choices))
        else:
            raise ValueError('Multiple ' + key + ' gateways; specify XRAY_' + key + '_PORT')
    return found, rows, template
