#!/usr/bin/env python3
"""Snell IPv4 TCP REDIRECT + UDP OUTPUT-mark/loopback TPROXY, with rollback."""
import configparser
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile

MARK = 0x534e
TABLE = 1988
PRIORITY = 1988
STATE = Path('/etc/snell/tproxy-state.json')


class Error(Exception):
    pass


def run(*args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, text=True)
    if p.returncode:
        raise Error(args[0] + ' failed (exit ' + str(p.returncode) + ')')
    return p.stdout


def policy_compatible(config, redirect_tag, tproxy_tag):
    # Inbound-specific rules must select the same path for both gateways.
    # Do not silently change the exit policy by switching the UDP inbound tag.
    def selected(tag):
        return [{k:v for k,v in rule.items() if k != 'inboundTag'}
                for rule in config.get('routing',{}).get('rules',[])
                if not rule.get('inboundTag') or tag in rule['inboundTag']]
    return selected(redirect_tag) == selected(tproxy_tag)


def verify_gateways(configs, redirect, tproxy, uid):
    choices = []
    for config in configs:
        inbounds = config.get('inbounds',[])
        red = [i for i in inbounds if i.get('listen')=='127.0.0.1' and i.get('port')==redirect]
        udp = [i for i in inbounds if i.get('listen')=='127.0.0.1' and i.get('port')==tproxy]
        if not red and not udp:
            continue
        if len(red)!=1 or len(udp)!=1:
            raise Error('TCP REDIRECT and UDP TPROXY must belong to one known Xray configuration')
        r,t = red[0],udp[0]
        for i, network in ((r,'tcp'),(t,'udp')):
            s=i.get('settings',{})
            if i.get('protocol')!='dokodemo-door' or s.get('followRedirect') is not True or network not in s.get('network','tcp').split(','):
                raise Error('Incompatible transparent Xray gateway')
        if t.get('streamSettings',{}).get('sockopt',{}).get('tproxy')!='tproxy':
            raise Error('UDP gateway requires IP_TRANSPARENT (sockopt.tproxy=tproxy)')
        if not policy_compatible(config,r.get('tag'),t.get('tag')):
            raise Error('Gateway routing policies differ; configure equivalent Snell UDP routing before applying')
        choices.append((r,t))
    if len(choices)!=1:
        raise Error('Cannot identify one active pair of Xray gateways')
    # proc socket tables identify the bound address/port and socket owner.
    expected='0100007F:'+format(tproxy,'04X')
    listeners=[line.split() for line in Path('/proc/net/udp').read_text().splitlines()[1:]
               if line.split()[1]==expected]
    if not listeners or any(int(line[7])==uid for line in listeners):
        raise Error('UDP TPROXY listener missing or owned by Snell (recursion risk)')
    with socket.create_connection(('127.0.0.1',redirect),timeout=3):
        pass


def build_rules(snapshot, table, mode, uid, port, addresses, redirect, tproxy):
    chains = ['SNELL_OUT'] if table=='nat' else ['SNELL_MARK','SNELL_TPROXY']
    lines=['*'+table]
    old=snapshot.splitlines()
    # Remove only our hooks/chains. Other services' tables/rules remain untouched.
    for line in old:
        if line.startswith('-A ') and any(line.endswith(' -j '+name) for name in chains):
            lines.append('-D '+line[3:])
    present=[name for name in chains if any(l.startswith(':'+name+' ') for l in old)]
    for name in present:
        lines.append('-F '+name)
    if mode=='direct':
        for name in present:
            lines.append('-X '+name)
    else:
        for name in chains:
            if name not in present:
                lines.append('-N '+name)
        chain=chains[0]
        for address in ['127.0.0.0/8',*addresses]:
            lines.append('-A '+chain+' -d '+address+' -j RETURN')
        # Reply direction, not ESTABLISHED: every outgoing UDP packet must be
        # marked, including subsequent requests in the same conntrack entry.
        lines.append('-A '+chain+' -m conntrack --ctdir REPLY -j RETURN')
        for proto in ('tcp','udp'):
            lines.append(f'-A {chain} -p {proto} --sport {port} -j RETURN')
        if table=='nat':
            lines += [f'-A SNELL_OUT -p tcp -j REDIRECT --to-ports {redirect}',
                      f'-I OUTPUT 1 -m owner --uid-owner {uid} -j SNELL_OUT']
        else:
            lines += [f'-A SNELL_MARK -p udp -j MARK --set-mark {MARK}',
                      f'-A SNELL_TPROXY -p udp -j TPROXY --on-ip 127.0.0.1 --on-port {tproxy} --tproxy-mark {MARK}',
                      f'-I OUTPUT 1 -p udp -m owner --uid-owner {uid} -j SNELL_MARK',
                      f'-I PREROUTING 1 -i lo -p udp -m mark --mark {MARK} -j SNELL_TPROXY']
    return '\n'.join(lines+['COMMIT',''])


def apply(mode, uid, port, addresses, redirect, tproxy, state=STATE, backup_root=Path('/var/backups')):
    if mode not in ('direct','xray'):
        raise Error('Unknown Snell routing mode')
    snapshots={table:run('iptables-save','-t',table) for table in ('nat','mangle')}
    rules=json.loads(run('ip','-j','-4','rule','show'))
    existing=[r for r in rules if r.get('priority')==PRIORITY or str(r.get('table'))==str(TABLE) or
              int(str(r.get('fwmark','0')),0)==MARK]
    routes=[r for r in json.loads(run('ip','-j','-4','route','show','table','all')) if str(r.get('table'))==str(TABLE)]
    owned=state.is_file() and json.loads(state.read_text())=={'table':TABLE,'priority':PRIORITY,'mark':MARK}
    if (existing or routes) and not owned:
        raise Error('Snell policy-routing table/priority occupied; refusing to change it')
    if existing and (len(existing)!=1 or existing[0].get('priority')!=PRIORITY or
                     str(existing[0].get('table'))!=str(TABLE) or
                     int(str(existing[0].get('fwmark','0')),0)!=MARK or
                     existing[0].get('src','all')!='all' or
                     existing[0].get('fwmask','0xffffffff') not in ('0xffffffff',4294967295)):
        raise Error('Unexpected rules in the Snell policy-routing slot')
    if routes and (len(routes)!=1 or routes[0].get('type')!='local' or routes[0].get('dev')!='lo' or routes[0].get('dst') not in ('default','0.0.0.0/0')):
        raise Error('Unexpected routes in the Snell table')
    desired={table:build_rules(snapshots[table],table,mode,uid,port,addresses,redirect,tproxy) for table in snapshots}
    for data in desired.values():
        run('iptables-restore','--test','--noflush','--wait','5',data=data)
    backup=Path(tempfile.mkdtemp(prefix='x-manager-snell-routing-',dir=backup_root))
    for table,data in snapshots.items():
        (backup/(table+'.rules')).write_text(data)
    (backup/'policy.json').write_text(json.dumps({'rules':existing,'routes':routes,'state':owned}))
    applied=[]; added_rule=False; added_route=False
    try:
        if mode=='xray':
            state.write_text(json.dumps({'table':TABLE,'priority':PRIORITY,'mark':MARK}))
            if not routes:
                run('ip','-4','route','add','local','0.0.0.0/0','dev','lo','table',str(TABLE));added_route=True
            if not existing:
                run('ip','-4','rule','add','priority',str(PRIORITY),'fwmark',str(MARK),'table',str(TABLE));added_rule=True
            path=json.loads(run('ip','-j','-4','route','get','198.18.255.254','mark',str(MARK)))[0]
            if path.get('type')!='local' or path.get('dev')!='lo' or str(path.get('table'))!=str(TABLE):
                raise Error('Policy rule is shadowed; marked UDP does not return through loopback')
        # Mark first, then remove legacy UDP NAT: no transient direct DNS bypass.
        for table in ('mangle','nat'):
            applied.append(table)
            run('iptables-restore','--noflush','--wait','5',data=desired[table])
        if mode=='direct' and owned:
            if existing:run('ip','-4','rule','del','priority',str(PRIORITY),'fwmark',str(MARK),'table',str(TABLE))
            if routes:run('ip','-4','route','del','local','0.0.0.0/0','dev','lo','table',str(TABLE))
            state.unlink()
        return backup
    except Exception:
        # Restore both tables exactly if kernel application fails. This path
        # is exceptional and guarded by the X-Manager routing lock.
        try:
            for table in reversed(applied):
                run('iptables-restore','--wait','5',data=snapshots[table])
            if added_rule:run('ip','-4','rule','del','priority',str(PRIORITY),'fwmark',str(MARK),'table',str(TABLE))
            if added_route:run('ip','-4','route','del','local','0.0.0.0/0','dev','lo','table',str(TABLE))
            if owned:
                current=json.loads(run('ip','-j','-4','rule','show'))
                if existing and not any(r.get('priority')==PRIORITY for r in current):
                    run('ip','-4','rule','add','priority',str(PRIORITY),'fwmark',str(MARK),'table',str(TABLE))
                current=json.loads(run('ip','-j','-4','route','show','table','all'))
                if routes and not any(str(r.get('table'))==str(TABLE) for r in current):
                    run('ip','-4','route','add','local','0.0.0.0/0','dev','lo','table',str(TABLE))
                state.write_text(json.dumps({'table':TABLE,'priority':PRIORITY,'mark':MARK}))
            else:
                state.unlink(missing_ok=True)
        except Exception:
            raise Error('Snell routing rollback incomplete; inspect backup: '+str(backup)) from None
        raise Error('Snell routing failed; previous rules restored; backup: '+str(backup)) from None


def main():
    if os.geteuid()!=0:
        raise Error('Run as root')
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('direct','xray'))
    args=parser.parse_args()
    mode_path=Path('/etc/snell/routing.mode')
    mode=args.mode or mode_path.read_text().strip()
    config=configparser.ConfigParser(interpolation=None)
    config.read('/etc/snell/snell-server.conf')
    section=config['snell-server']
    port=int(section['listen'].rsplit(':',1)[1])
    uid=pwd.getpwnam('snell').pw_uid
    env={}
    env_path=Path('/etc/x-manager/gateways.env')
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if re.fullmatch(r'XRAY_\w+_PORT=\d+',line):
                key,value=line.split('=');env[key]=int(value)
    redirect,tproxy=env.get('XRAY_REDIRECT_PORT',12346),env.get('XRAY_TPROXY_PORT',12345)
    if any(p in (443,8443) or not 1<=p<=65535 for p in (redirect,tproxy)):
        raise Error('Invalid gateway port')
    if mode=='xray':
        if section.getboolean('ipv6',fallback=False):
            raise Error('IPv6 Snell needs an explicit IPv6 transparent gateway; IPv4-only routing cannot be applied')
        spec=importlib.util.spec_from_file_location('discovery',Path(__file__).with_name('xray-discovery.py'))
        discovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(discovery)
        paths=discovery.paths()
        configs=[discovery.jsonc(p.read_text()) for p in paths]
        verify_gateways(configs,redirect,tproxy,uid)
    addresses=sorted({a['local'] for interface in json.loads(run('ip','-j','-4','address','show'))
                      for a in interface.get('addr_info',[]) if a['local']!='127.0.0.1'})
    with open('/run/lock/x-manager-snell-routing.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        action=lambda selected: apply(selected,uid,port,addresses,redirect,tproxy)
        backup=change_mode(mode_path, mode, action) if args.mode else action(mode)
    print('Snell routing applied: '+mode+'; backup: '+str(backup))


def change_mode(path, mode, action):
    """Persist a menu choice only after successful routing, under caller's lock."""
    previous=path.read_bytes()
    old=previous.decode().strip()
    if old not in ('direct','xray'):
        raise Error('Invalid saved Snell routing mode')
    # Prepare the write before changing kernel state (read-only filesystem, etc.).
    fd,name=tempfile.mkstemp(prefix='.routing.mode-',dir=path.parent)
    os.close(fd)
    temp=Path(name)
    try:
        shutil.copy2(path,temp)
        os.chown(temp,path.stat().st_uid,path.stat().st_gid)
        temp.write_text(mode+'\n')
        backup=action(mode)
        try:
            (backup/'routing.mode.before').write_bytes(previous)
            os.replace(temp,path)
        except Exception:
            action(old)
            raise Error('Could not save routing mode; previous routing restored') from None
        return backup
    finally:
        temp.unlink(missing_ok=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('Snell routing error: '+(str(e) if isinstance(e,Error) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
