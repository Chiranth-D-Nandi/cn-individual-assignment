#!/usr/bin/env python3
"""
Multi-Switch Flow Table Analyzer
No Ryu needed - reads OVS tables directly via ovs-ofctl
"""

import subprocess
import time
import os
import json
import re
from datetime import datetime


class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def col(text, color):
    return f"{color}{text}{C.RESET}"

def header(title):
    print("\n" + col("="*65, C.CYAN))
    print(col(f"  {title}", C.BOLD))
    print(col("="*65, C.CYAN))

def section(title):
    pad = max(0, 55 - len(title))
    print("\n" + col(f"--- {title} ", C.YELLOW) + col("-"*pad, C.YELLOW))


def get_switches():
    try:
        r = subprocess.run(
            ['sudo', 'ovs-vsctl', 'list-br'],
            capture_output=True, text=True
        )
        return [s.strip() for s in r.stdout.strip().split('\n') if s.strip()]
    except:
        return []


def get_flows(switch):
    try:
        r = subprocess.run(
            ['sudo', 'ovs-ofctl', 'dump-flows', switch],
            capture_output=True, text=True
        )
        return parse_flows(r.stdout, switch)
    except Exception as e:
        print(col(f"Error reading {switch}: {e}", C.RED))
        return []


def parse_flows(raw, switch):
    flows = []
    for line in raw.strip().split('\n'):
        line = line.strip()
        if 'cookie' not in line:
            continue

        def search(pattern, default='0'):
            m = re.search(pattern, line)
            return m.group(1) if m else default

        flows.append({
            'switch'  : switch,
            'raw'     : line,
            'priority': int(search(r'priority=(\d+)')),
            'packets' : int(search(r'n_packets=(\d+)')),
            'bytes'   : int(search(r'n_bytes=(\d+)')),
            'duration': float(search(r'duration=([\d.]+)s', '0')),
            'actions' : search(r'actions=(.+)$', 'drop'),
            'match'   : extract_match(line),
            'cookie'  : search(r'cookie=([\S]+?)(?:,|\s|$)'),
            'table'   : search(r'table=(\d+)'),
            'idle_to' : search(r'idle_timeout=(\d+)', 'none'),
            'hard_to' : search(r'hard_timeout=(\d+)', 'none'),
        })
    return flows


def extract_match(line):
    checks = [
        (r'in_port=([\w]+)',               'in_port'),
        (r'(?:dl_src|eth_src)=([\w:]+)',   'src_mac'),
        (r'(?:dl_dst|eth_dst)=([\w:]+)',   'dst_mac'),
        (r'(?:nw_src|ip_src)=([\d.\/]+)',  'src_ip'),
        (r'(?:nw_dst|ip_dst)=([\d.\/]+)',  'dst_ip'),
        (r'(?:dl_type|eth_type)=(0x\w+)',  'eth_type'),
    ]
    fields = []
    for pattern, label in checks:
        m = re.search(pattern, line)
        if m:
            fields.append(f"{label}={m.group(1)}")
    return ', '.join(fields) if fields else 'ANY (table-miss)'


def get_status(flow):
    if flow['priority'] == 0 or flow['priority'] == 65534:
        return 'DEFAULT', C.BLUE
    if flow['packets'] > 0:
        return 'ACTIVE',  C.GREEN
    if flow['duration'] < 15:
        return 'NEW',     C.YELLOW
    return 'UNUSED', C.RED


def show_switch_table(switch, flows):
    section(f"Switch: {switch}  ({len(flows)} rules)")
    if not flows:
        print(col("  No flows found.", C.RED))
        return

    print(col(
        f"  {'#':<4}{'Pri':<8}{'Pkts':<8}{'Bytes':<10}"
        f"{'Dur(s)':<9}{'Match':<32}{'Actions':<20}Status",
        C.BOLD
    ))
    print("  " + col("-"*100, C.BLUE))

    for i, f in enumerate(flows, 1):
        st, sc = get_status(f)
        match_s  = (f['match'][:30]   + '..') if len(f['match'])   > 32 else f['match']
        action_s = (f['actions'][:18] + '..') if len(f['actions']) > 20 else f['actions']
        print(
            f"  {i:<4}{f['priority']:<8}{f['packets']:<8}{f['bytes']:<10}"
            f"{f['duration']:<9.1f}{match_s:<32}{action_s:<20}" + col(st, sc)
        )


def show_detail(flow, num):
    print(f"\n  {col(f'Flow #{num}', C.BOLD)}")
    for k, v in [
        ('Switch',       flow['switch']),
        ('Priority',     flow['priority']),
        ('Table',        flow['table']),
        ('Cookie',       flow['cookie']),
        ('Match',        flow['match']),
        ('Actions',      flow['actions']),
        ('Packets',      flow['packets']),
        ('Bytes',        flow['bytes']),
        ('Duration(s)',  flow['duration']),
        ('Idle Timeout', flow['idle_to']),
        ('Hard Timeout', flow['hard_to']),
        ('Status',       col(*get_status(flow))),
    ]:
        print(f"    {col(k+':', C.CYAN):<28}{v}")


def show_summary(all_flows):
    section("SUMMARY — All Switches")
    by_sw = {}
    for f in all_flows:
        sw = f['switch']
        if sw not in by_sw:
            by_sw[sw] = {'total':0,'active':0,'unused':0,'new':0,'default':0}
        by_sw[sw]['total'] += 1
        st, _ = get_status(f)
        by_sw[sw][st.lower()] += 1

    print(col(f"\n  {'Switch':<10}{'Total':<8}{'Active':<10}{'Unused':<10}{'New':<8}{'Default'}", C.BOLD))
    print("  " + col("-"*55, C.BLUE))

    total_all = active_all = unused_all = 0
    for sw, c in by_sw.items():
        print(
            f"  {sw:<10}{c['total']:<8}"
            f"{col(str(c['active']), C.GREEN):<19}"
            f"{col(str(c['unused']), C.RED):<19}"
            f"{col(str(c['new']), C.YELLOW):<17}"
            f"{col(str(c['default']), C.BLUE)}"
        )
        total_all  += c['total']
        active_all += c['active']
        unused_all += c['unused']

    print("  " + col("-"*55, C.BLUE))
    print(
        f"  {'TOTAL':<10}{total_all:<8}"
        f"{col(str(active_all), C.GREEN):<19}"
        f"{col(str(unused_all), C.RED)}"
    )

    total_pkts  = sum(f['packets'] for f in all_flows)
    total_bytes = sum(f['bytes']   for f in all_flows)
    eff = (active_all / total_all * 100) if total_all else 0

    print(f"\n  Total packets   : {col(str(total_pkts),  C.CYAN)}")
    print(f"  Total bytes     : {col(str(total_bytes), C.CYAN)}")
    print(f"  Rule efficiency : {col(f'{eff:.1f}%',    C.YELLOW)}")


def show_active_vs_unused(all_flows):
    section("ACTIVE RULES  (matched traffic)")
    active = [f for f in all_flows if get_status(f)[0] == 'ACTIVE']
    if not active:
        print(col("  None yet — run 'pingall' in Mininet first!", C.YELLOW))
    for f in active:
        print(col(
            f"  [{f['switch']}] pri={f['priority']} "
            f"pkts={f['packets']} bytes={f['bytes']} "
            f"| {f['match']} → {f['actions']}",
            C.GREEN
        ))

    section("UNUSED RULES  (never matched — consider removing)")
    unused = [f for f in all_flows if get_status(f)[0] == 'UNUSED']
    if not unused:
        print(col("  None — every installed rule has been used!", C.GREEN))
    for f in unused:
        print(col(
            f"  [{f['switch']}] pri={f['priority']} "
            f"duration={f['duration']:.0f}s "
            f"| {f['match']} → {f['actions']}",
            C.RED
        ))


def save_report(all_flows):
    ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
    jfile = f'flow_report_{ts}.json'
    tfile = f'flow_report_{ts}.txt'

    with open(jfile, 'w') as fp:
        json.dump({
            'timestamp'  : datetime.now().isoformat(),
            'total_flows': len(all_flows),
            'switches'   : list(set(f['switch'] for f in all_flows)),
            'flows'      : all_flows
        }, fp, indent=2)

    with open(tfile, 'w') as fp:
        fp.write(f"Flow Table Report  {datetime.now()}\n{'='*60}\n\n")
        for f in all_flows:
            st, _ = get_status(f)
            fp.write(
                f"[{f['switch']}] {st:<8} pri={f['priority']} "
                f"pkts={f['packets']} | {f['match']} → {f['actions']}\n"
            )

    print(col(f"\n  Saved: {jfile}", C.GREEN))
    print(col(f"  Saved: {tfile}", C.GREEN))


def single_analysis():
    header("MULTI-SWITCH FLOW TABLE ANALYZER")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    switches = get_switches()
    if not switches:
        print(col("\n  No switches found!", C.RED))
        print("  → Start Mininet first:  sudo python3 topology.py")
        return

    print(f"  Switches found: {col(str(switches), C.GREEN)}")

    all_flows = []
    for sw in switches:
        flows = get_flows(sw)
        all_flows.extend(flows)
        show_switch_table(sw, flows)

    print(f"\n  Total flows retrieved: {col(str(len(all_flows)), C.CYAN)}")

    section("DETAILED INFO — first 3 rules")
    for i, f in enumerate(all_flows[:3], 1):
        show_detail(f, i)

    show_summary(all_flows)
    show_active_vs_unused(all_flows)
    save_report(all_flows)


def dynamic_monitor(interval=5):
    header("DYNAMIC FLOW MONITOR")
    print(f"  Refresh every {interval}s  |  Ctrl+C to stop")
    iteration = 0
    try:
        while True:
            os.system('clear')
            iteration += 1
            header(f"FLOW TABLE ANALYZER — Update #{iteration}")
            print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  (Ctrl+C to stop)")

            switches = get_switches()
            if not switches:
                print(col("\n  No switches — is Mininet running?", C.RED))
            else:
                all_flows = []
                for sw in switches:
                    flows = get_flows(sw)
                    all_flows.extend(flows)
                    show_switch_table(sw, flows)
                show_summary(all_flows)
                show_active_vs_unused(all_flows)

            print(col(f"\n  Next refresh in {interval}s...", C.BLUE))
            time.sleep(interval)
    except KeyboardInterrupt:
        print(col("\n  Monitor stopped.", C.YELLOW))


def main():
    header("MULTI-SWITCH FLOW TABLE ANALYZER")
    print("  No Ryu needed — reads OVS tables directly\n")
    print(col("  1", C.CYAN) + "  Single analysis snapshot")
    print(col("  2", C.CYAN) + "  Dynamic monitor (live refresh)")
    print(col("  3", C.CYAN) + "  Raw dump (debug / see everything)")
    print(col("  q", C.CYAN) + "  Quit")

    choice = input("\n  Choice: ").strip().lower()

    if choice == '1':
        single_analysis()
    elif choice == '2':
        try:
            iv = int(input("  Refresh interval in seconds [5]: ") or "5")
        except ValueError:
            iv = 5
        dynamic_monitor(iv)
    elif choice == '3':
        for sw in get_switches():
            print(col(f"\n{'='*50}\nRAW FLOWS: {sw}\n{'='*50}", C.YELLOW))
            r = subprocess.run(
                ['sudo', 'ovs-ofctl', 'dump-flows', sw],
                capture_output=True, text=True
            )
            print(r.stdout)
    elif choice == 'q':
        print("  Bye!")
    else:
        print(col("  Invalid choice.", C.RED))


if __name__ == '__main__':
    main()
