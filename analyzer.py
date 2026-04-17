#!/usr/bin/env python3
"""
Multi-Switch Flow Table Analyzer
Works with POX Controller + OVS Switches

This script:
1. Queries OVS switches directly using ovs-ofctl commands
2. Parses flow table entries
3. Displays active vs unused rules
4. Updates dynamically
5. Generates reports

Run AFTER starting POX controller and Mininet topology.
"""

import subprocess
import json
import time
import os
import re
import sys
from datetime import datetime


# ============================================================
# TERMINAL COLORS
# ============================================================

class Colors:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def C(text, color):
    """Apply color to text"""
    return f"{color}{text}{Colors.RESET}"

def print_header(title):
    """Print a big section header"""
    width = 72
    line  = "=" * width
    print("\n" + C(line, Colors.CYAN))
    print(C(f"  {title}", Colors.BOLD + Colors.WHITE))
    print(C(line, Colors.CYAN))

def print_section(title):
    """Print a smaller section separator"""
    print("\n" + C(f"--- {title} ---", Colors.YELLOW + Colors.BOLD))


# ============================================================
# SWITCH DISCOVERY
# ============================================================

def get_switches():
    """
    Get all OVS bridges (switches) currently running.
    Returns list of switch names like ['s1', 's2', 's3']
    """
    try:
        result = subprocess.run(
            ['sudo', 'ovs-vsctl', 'list-br'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return []

        # Split output into list, remove empty strings
        switches = [
            s.strip()
            for s in result.stdout.strip().split('\n')
            if s.strip()
        ]

        return switches

    except subprocess.TimeoutExpired:
        print(C("Timeout getting switch list", Colors.RED))
        return []
    except Exception as e:
        print(C(f"Error getting switches: {e}", Colors.RED))
        return []


def get_switch_dpid(switch_name):
    """Get the DPID (datapath ID) of a switch"""
    try:
        result = subprocess.run(
            ['sudo', 'ovs-vsctl', 'get', 'bridge', switch_name,
             'datapath_id'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().strip('"')
        return "unknown"
    except Exception:
        return "unknown"


# ============================================================
# FLOW TABLE RETRIEVAL
# ============================================================

def get_flow_table(switch_name):
    """
    Get flow table from a specific OVS switch.
    Uses ovs-ofctl dump-flows command.
    Returns list of parsed flow dictionaries.
    """
    try:
        # Try OpenFlow 1.3 first
        result = subprocess.run(
            ['sudo', 'ovs-ofctl',
             '-O', 'OpenFlow13',
             'dump-flows', switch_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Fall back to OpenFlow 1.0 if 1.3 fails
        if result.returncode != 0:
            result = subprocess.run(
                ['sudo', 'ovs-ofctl',
                 'dump-flows', switch_name],
                capture_output=True,
                text=True,
                timeout=10
            )

        if result.returncode != 0:
            print(C(
                f"  Cannot read {switch_name}: {result.stderr.strip()}",
                Colors.RED
            ))
            return []

        # Parse the output
        flows = parse_flow_output(result.stdout, switch_name)
        return flows

    except subprocess.TimeoutExpired:
        print(C(f"  Timeout reading {switch_name}", Colors.RED))
        return []
    except Exception as e:
        print(C(f"  Error reading {switch_name}: {e}", Colors.RED))
        return []


# ============================================================
# FLOW OUTPUT PARSER
# ============================================================

def parse_flow_output(raw_output, switch_name):
    """
    Parse raw ovs-ofctl dump-flows output.

    Example input line:
    cookie=0x0, duration=45.123s, table=0, n_packets=12,
    n_bytes=936, idle_timeout=30, hard_timeout=120,
    priority=1,in_port=1,dl_src=00:00:00:00:00:01,
    dl_dst=00:00:00:00:00:03 actions=output:3

    Returns list of flow dictionaries.
    """
    flows = []
    lines = raw_output.strip().split('\n')

    for line in lines:
        line = line.strip()

        # Skip empty lines and header
        if not line:
            continue
        if 'OFPST_FLOW' in line:
            continue
        if 'cookie' not in line:
            continue

        # Parse each field
        flow = {
            'switch'       : switch_name,
            'raw'          : line,
            'cookie'       : _extract(line, 'cookie') or '0x0',
            'duration'     : _extract_duration(line),
            'table'        : _extract(line, 'table') or '0',
            'n_packets'    : int(_extract(line, 'n_packets') or 0),
            'n_bytes'      : int(_extract(line, 'n_bytes')   or 0),
            'priority'     : _extract_priority(line),
            'idle_timeout' : _extract(line, 'idle_timeout') or '0',
            'hard_timeout' : _extract(line, 'hard_timeout') or '0',
            'in_port'      : _extract(line, 'in_port'),
            'src_mac'      : _extract_mac(line, 'src'),
            'dst_mac'      : _extract_mac(line, 'dst'),
            'src_ip'       : _extract_ip(line, 'src'),
            'dst_ip'       : _extract_ip(line, 'dst'),
            'match'        : _build_match_string(line),
            'actions'      : _extract_actions(line),
            'timestamp'    : datetime.now().strftime('%H:%M:%S')
        }

        flows.append(flow)

    return flows


# ============================================================
# PARSING HELPER FUNCTIONS
# ============================================================

def _extract(line, key):
    """Extract value from 'key=value' pattern"""
    pattern = rf'(?<![a-z_]){re.escape(key)}=([^\s,]+)'
    match   = re.search(pattern, line)
    if match:
        return match.group(1)
    return None


def _extract_duration(line):
    """Extract duration in seconds as float"""
    match = re.search(r'duration=([\d.]+)s', line)
    if match:
        return float(match.group(1))
    return 0.0


def _extract_priority(line):
    """Extract priority as integer"""
    match = re.search(r'priority=(\d+)', line)
    if match:
        return int(match.group(1))
    return 0


def _extract_mac(line, direction):
    """
    Extract MAC address for src or dst.
    Handles both dl_src/dl_dst and eth_src/eth_dst formats.
    """
    if direction == 'src':
        patterns = [r'dl_src=([\w:]+)', r'eth_src=([\w:]+)']
    else:
        patterns = [r'dl_dst=([\w:]+)', r'eth_dst=([\w:]+)']

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def _extract_ip(line, direction):
    """Extract IP address for src or dst"""
    if direction == 'src':
        patterns = [r'nw_src=([\d.]+)', r'ip_src=([\d.]+)']
    else:
        patterns = [r'nw_dst=([\d.]+)', r'ip_dst=([\d.]+)']

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def _build_match_string(line):
    """
    Build a human-readable match string from the flow line.
    Shows all matched fields in a clean format.
    """
    fields = []

    # In port
    port = _extract(line, 'in_port')
    if port:
        fields.append(f"port={port}")

    # Source MAC
    src_mac = _extract_mac(line, 'src')
    if src_mac:
        fields.append(f"src={src_mac}")

    # Destination MAC
    dst_mac = _extract_mac(line, 'dst')
    if dst_mac:
        fields.append(f"dst={dst_mac}")

    # Source IP
    src_ip = _extract_ip(line, 'src')
    if src_ip:
        fields.append(f"src_ip={src_ip}")

    # Destination IP
    dst_ip = _extract_ip(line, 'dst')
    if dst_ip:
        fields.append(f"dst_ip={dst_ip}")

    # ARP
    if 'arp' in line.lower():
        fields.append("ARP")

    # IP protocol
    if 'ip' in line.split('actions=')[0].lower():
        dl_type = _extract(line, 'dl_type')
        if dl_type:
            fields.append(f"type={dl_type}")

    if not fields:
        return "ANY (table-miss)"

    return ", ".join(fields)


def _extract_actions(line):
    """Extract the actions section from flow line"""
    if 'actions=' in line:
        action_part = line.split('actions=')[1].strip()
        return action_part
    return "drop"


# ============================================================
# FLOW STATUS CLASSIFICATION
# ============================================================

def classify_flow(flow):
    """
    Classify a flow as one of:
    - DEFAULT  : table-miss rule (priority=0)
    - ACTIVE   : has matched packets (n_packets > 0)
    - NEW      : just installed, no packets yet (duration < 30s)
    - UNUSED   : been there a while but zero packets
    - IDLE     : had traffic but may be expiring soon

    Returns (status_string, color_code)
    """
    packets  = flow['n_packets']
    duration = flow['duration']
    priority = flow['priority']

    # Table-miss rule
    if priority == 0:
        return ("DEFAULT", Colors.BLUE)

    # Has matched traffic
    if packets > 0:
        if packets > 50:
            return ("ACTIVE-HIGH", Colors.GREEN)
        else:
            return ("ACTIVE", Colors.GREEN)

    # Zero packets
    if packets == 0:
        if duration < 30:
            return ("NEW", Colors.YELLOW)
        elif duration < 120:
            return ("UNUSED", Colors.RED)
        else:
            return ("STALE", Colors.PURPLE)

    return ("UNKNOWN", Colors.WHITE)


# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

def display_flow_table(switch_name, flows):
    """
    Display flow table for one switch as a formatted table.
    Shows all flow entries with their key fields.
    """
    dpid = get_switch_dpid(switch_name)

    print_section(
        f"Switch: {C(switch_name, Colors.WHITE)} "
        f"(DPID: {dpid}) - "
        f"{C(str(len(flows)), Colors.WHITE)} flows"
    )

    if not flows:
        print(C("  [No flow entries found]", Colors.RED))
        print(C(
            "  Hint: Generate traffic first (pingall in Mininet)",
            Colors.YELLOW
        ))
        return

    # ---- Table Header ----
    col_widths = {
        'num'     : 4,
        'pri'     : 8,
        'pkts'    : 8,
        'bytes'   : 10,
        'dur'     : 8,
        'match'   : 40,
        'actions' : 18,
        'status'  : 12,
    }

    header = (
        f"{'#':<{col_widths['num']}} "
        f"{'Pri':<{col_widths['pri']}} "
        f"{'Packets':<{col_widths['pkts']}} "
        f"{'Bytes':<{col_widths['bytes']}} "
        f"{'Dur(s)':<{col_widths['dur']}} "
        f"{'Match Fields':<{col_widths['match']}} "
        f"{'Actions':<{col_widths['actions']}} "
        f"{'Status':<{col_widths['status']}}"
    )

    print(C(header, Colors.BOLD))
    print(C("-" * 118, Colors.BLUE))

    # ---- Table Rows ----
    for i, flow in enumerate(flows, 1):
        status, status_color = classify_flow(flow)

        # Truncate long fields to fit columns
        match_str  = flow['match']
        action_str = flow['actions']

        if len(match_str) > col_widths['match'] - 2:
            match_str = match_str[:col_widths['match'] - 3] + ".."

        if len(action_str) > col_widths['actions'] - 2:
            action_str = action_str[:col_widths['actions'] - 3] + ".."

        # Build row
        row = (
            f"{i:<{col_widths['num']}} "
            f"{flow['priority']:<{col_widths['pri']}} "
            f"{flow['n_packets']:<{col_widths['pkts']}} "
            f"{flow['n_bytes']:<{col_widths['bytes']}} "
            f"{flow['duration']:<{col_widths['dur']}.1f} "
            f"{match_str:<{col_widths['match']}} "
            f"{action_str:<{col_widths['actions']}} "
        )

        print(row + C(f"{status:<{col_widths['status']}}", status_color))

    print()


def display_detailed_rule(flow, index):
    """Show all fields for a single flow rule"""
    status, color = classify_flow(flow)

    print(f"\n  {C(f'[Flow #{index}]', Colors.BOLD + Colors.CYAN)}")
    print(f"  {'Field':<22} {'Value'}")
    print(f"  {'-' * 55}")
    print(f"  {'Switch':<22} {C(flow['switch'], Colors.WHITE)}")
    print(f"  {'Status':<22} {C(status, color)}")
    print(f"  {'Priority':<22} {flow['priority']}")
    print(f"  {'Table ID':<22} {flow['table']}")
    print(f"  {'Cookie':<22} {flow['cookie']}")
    print(f"  {'Match':<22} {flow['match']}")

    if flow['in_port']:
        print(f"  {'  In Port':<22} {flow['in_port']}")
    if flow['src_mac']:
        print(f"  {'  Src MAC':<22} {flow['src_mac']}")
    if flow['dst_mac']:
        print(f"  {'  Dst MAC':<22} {flow['dst_mac']}")
    if flow['src_ip']:
        print(f"  {'  Src IP':<22} {flow['src_ip']}")
    if flow['dst_ip']:
        print(f"  {'  Dst IP':<22} {flow['dst_ip']}")

    print(f"  {'Actions':<22} {C(flow['actions'], Colors.CYAN)}")
    print(f"  {'Packets Matched':<22} {C(str(flow['n_packets']), Colors.GREEN if flow['n_packets'] > 0 else Colors.RED)}")
    print(f"  {'Bytes Matched':<22} {flow['n_bytes']}")
    print(f"  {'Duration (sec)':<22} {flow['duration']:.2f}")
    print(f"  {'Idle Timeout':<22} {flow['idle_timeout']}s")
    print(f"  {'Hard Timeout':<22} {flow['hard_timeout']}s")
    print(f"  {'Last Updated':<22} {flow['timestamp']}")


def display_active_vs_unused(all_flows):
    """
    Show two sections:
    1. All ACTIVE rules (matched traffic)
    2. All UNUSED rules (zero matches)
    """

    # ---- Active Rules ----
    print_section("ACTIVE RULES  (have matched traffic)")

    active_flows = [
        f for f in all_flows
        if classify_flow(f)[0] in ('ACTIVE', 'ACTIVE-HIGH')
    ]

    if not active_flows:
        print(C(
            "  No active flows yet. Run 'pingall' in Mininet first.",
            Colors.YELLOW
        ))
    else:
        print(C(
            f"  {len(active_flows)} active rules found:\n",
            Colors.GREEN
        ))
        for flow in active_flows:
            status, _ = classify_flow(flow)
            print(C(
                f"  [{flow['switch']}] "
                f"Pri={flow['priority']}  "
                f"Pkts={flow['n_packets']:>6}  "
                f"Bytes={flow['n_bytes']:>8}  "
                f"Match: {flow['match'][:45]}  "
                f"=> {flow['actions']}",
                Colors.GREEN
            ))

    # ---- Unused Rules ----
    print_section("UNUSED RULES  (zero packet matches)")

    unused_flows = [
        f for f in all_flows
        if classify_flow(f)[0] in ('UNUSED', 'STALE')
    ]

    if not unused_flows:
        print(C(
            "  No unused rules found!",
            Colors.GREEN
        ))
        print(C(
            "  All installed rules are actively matching traffic.",
            Colors.GREEN
        ))
    else:
        print(C(
            f"  WARNING: {len(unused_flows)} unused rules detected "
            f"(consider removing to save table space):\n",
            Colors.YELLOW
        ))
        for flow in unused_flows:
            status, _ = classify_flow(flow)
            print(C(
                f"  [{flow['switch']}] "
                f"Pri={flow['priority']}  "
                f"Duration={flow['duration']:.0f}s  "
                f"Match: {flow['match'][:45]}  "
                f"=> {flow['actions']}",
                Colors.RED
            ))

    # ---- New/Pending Rules ----
    new_flows = [
        f for f in all_flows
        if classify_flow(f)[0] == 'NEW'
    ]

    if new_flows:
        print_section("NEW RULES  (just installed, awaiting traffic)")
        for flow in new_flows:
            print(C(
                f"  [{flow['switch']}] "
                f"Pri={flow['priority']}  "
                f"Duration={flow['duration']:.0f}s  "
                f"Match: {flow['match'][:45]}",
                Colors.YELLOW
            ))


def display_summary(all_flows):
    """
    Display summary table with per-switch breakdown
    and overall statistics.
    """
    print_section("SUMMARY  -  All Switches")

    if not all_flows:
        print(C("  No flows to summarize.", Colors.YELLOW))
        return

    # ---- Per-Switch Counts ----
    by_switch = {}
    for flow in all_flows:
        sw = flow['switch']
        if sw not in by_switch:
            by_switch[sw] = {
                'total'   : 0,
                'active'  : 0,
                'unused'  : 0,
                'new'     : 0,
                'default' : 0,
                'packets' : 0,
                'bytes'   : 0,
            }

        status, _ = classify_flow(flow)
        by_switch[sw]['total']   += 1
        by_switch[sw]['packets'] += flow['n_packets']
        by_switch[sw]['bytes']   += flow['n_bytes']

        if status in ('ACTIVE', 'ACTIVE-HIGH'):
            by_switch[sw]['active']  += 1
        elif status in ('UNUSED', 'STALE'):
            by_switch[sw]['unused']  += 1
        elif status == 'NEW':
            by_switch[sw]['new']     += 1
        elif status == 'DEFAULT':
            by_switch[sw]['default'] += 1

    # ---- Print Per-Switch Table ----
    print()
    header = (
        f"  {'Switch':<10} "
        f"{'Total':<8} "
        f"{'Active':<9} "
        f"{'Unused':<9} "
        f"{'New':<6} "
        f"{'Default':<9} "
        f"{'Packets':<10} "
        f"{'Bytes':<12}"
    )
    print(C(header, Colors.BOLD))
    print(C("  " + "-" * 80, Colors.BLUE))

    grand_total   = 0
    grand_active  = 0
    grand_unused  = 0
    grand_packets = 0
    grand_bytes   = 0

    for sw in sorted(by_switch.keys()):
        d = by_switch[sw]
        print(
            f"  {C(sw, Colors.WHITE):<19} "
            f"{d['total']:<8} "
            f"{C(str(d['active']), Colors.GREEN):<18} "
            f"{C(str(d['unused']), Colors.RED):<18} "
            f"{C(str(d['new']), Colors.YELLOW):<15} "
            f"{C(str(d['default']), Colors.BLUE):<18} "
            f"{d['packets']:<10} "
            f"{d['bytes']:<12}"
        )
        grand_total   += d['total']
        grand_active  += d['active']
        grand_unused  += d['unused']
        grand_packets += d['packets']
        grand_bytes   += d['bytes']

    print(C("  " + "-" * 80, Colors.BLUE))
    print(
        f"  {'TOTAL':<10} "
        f"{grand_total:<8} "
        f"{C(str(grand_active), Colors.GREEN):<18} "
        f"{C(str(grand_unused), Colors.RED):<18} "
        f"{'':6} "
        f"{'':9} "
        f"{grand_packets:<10} "
        f"{grand_bytes:<12}"
    )

    # ---- Statistics ----
    print_section("Key Metrics")

    print(f"  {'Total flow entries':<28} : {C(str(grand_total), Colors.WHITE)}")
    print(f"  {'Active (matched traffic)':<28} : {C(str(grand_active), Colors.GREEN)}")
    print(f"  {'Unused (zero matches)':<28} : {C(str(grand_unused), Colors.RED)}")
    print(f"  {'Total packets matched':<28} : {C(str(grand_packets), Colors.CYAN)}")
    print(f"  {'Total bytes matched':<28} : {C(str(grand_bytes), Colors.CYAN)}")

    if grand_total > 0:
        efficiency = (grand_active / grand_total) * 100
        color = (Colors.GREEN if efficiency > 70
                 else Colors.YELLOW if efficiency > 40
                 else Colors.RED)
        print(f"  {'Rule efficiency':<28} : {C(f'{efficiency:.1f}%', color)}")

        if grand_unused > 0:
            print(C(
                f"\n  RECOMMENDATION: {grand_unused} unused rules detected. "
                f"Consider removing them to free up flow table space.",
                Colors.YELLOW
            ))


# ============================================================
# ALL FLOWS GETTER
# ============================================================

def get_all_flows(switches):
    """Retrieve flows from all switches and combine"""
    all_flows = []
    for sw in switches:
        flows = get_flow_table(sw)
        all_flows.extend(flows)
    return all_flows


# ============================================================
# REPORT GENERATOR
# ============================================================

def save_report(all_flows, switches):
    """Save analysis report to JSON and text files"""
    print_section("Saving Report")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # ---- Calculate Summary ----
    active_flows  = [f for f in all_flows if classify_flow(f)[0] in ('ACTIVE', 'ACTIVE-HIGH')]
    unused_flows  = [f for f in all_flows if classify_flow(f)[0] in ('UNUSED', 'STALE')]

    summary = {
        'timestamp'     : datetime.now().isoformat(),
        'switches'      : switches,
        'total_flows'   : len(all_flows),
        'active_count'  : len(active_flows),
        'unused_count'  : len(unused_flows),
        'total_packets' : sum(f['n_packets'] for f in all_flows),
        'total_bytes'   : sum(f['n_bytes']   for f in all_flows),
    }

    # ---- Save JSON ----
    json_file = f'flow_report_{timestamp}.json'
    report_data = {
        'summary' : summary,
        'flows'   : [
            {k: v for k, v in f.items() if k != 'raw'}
            for f in all_flows
        ]
    }

    with open(json_file, 'w') as f:
        json.dump(report_data, f, indent=2)

    print(C(f"  JSON report : {json_file}", Colors.GREEN))

    # ---- Save Text ----
    txt_file = f'flow_report_{timestamp}.txt'
    with open(txt_file, 'w') as f:

        f.write("MULTI-SWITCH FLOW TABLE ANALYSIS REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated  : {summary['timestamp']}\n")
        f.write(f"Switches   : {', '.join(summary['switches'])}\n")
        f.write(f"Total Flows: {summary['total_flows']}\n")
        f.write(f"Active     : {summary['active_count']}\n")
        f.write(f"Unused     : {summary['unused_count']}\n")
        f.write(f"Packets    : {summary['total_packets']}\n")
        f.write(f"Bytes      : {summary['total_bytes']}\n")
        f.write("\n" + "=" * 60 + "\n")
        f.write("FLOW ENTRIES\n")
        f.write("=" * 60 + "\n\n")

        for i, flow in enumerate(all_flows, 1):
            status, _ = classify_flow(flow)
            f.write(
                f"[{i:03d}] [{flow['switch']}] {status}\n"
                f"      Priority : {flow['priority']}\n"
                f"      Match    : {flow['match']}\n"
                f"      Actions  : {flow['actions']}\n"
                f"      Packets  : {flow['n_packets']}\n"
                f"      Bytes    : {flow['n_bytes']}\n"
                f"      Duration : {flow['duration']:.1f}s\n"
                f"\n"
            )

    print(C(f"  Text report : {txt_file}", Colors.GREEN))


# ============================================================
# RUN MODES
# ============================================================

def run_single_analysis():
    """One-time snapshot of all flow tables"""

    print_header("SINGLE ANALYSIS - Flow Table Snapshot")
    print(C(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.CYAN))

    # ---- Discover Switches ----
    print("\n[*] Discovering switches...")
    switches = get_switches()

    if not switches:
        print(C(
            "\n  ERROR: No OVS switches found!\n"
            "  Make sure Mininet is running:\n"
            "    sudo python3 topology.py",
            Colors.RED
        ))
        return

    print(f"[+] Found {len(switches)} switch(es): {C(str(switches), Colors.GREEN)}")

    # ---- Get Flows ----
    print("\n[*] Reading flow tables...")
    all_flows = get_all_flows(switches)
    print(f"[+] Total flows: {C(str(len(all_flows)), Colors.WHITE)}")

    # ---- Display Per-Switch Tables ----
    for sw in switches:
        sw_flows = [f for f in all_flows if f['switch'] == sw]
        display_flow_table(sw, sw_flows)

    # ---- Detailed View of First Few Flows ----
    print_section("DETAILED RULE INFORMATION (first 6 flows)")
    for i, flow in enumerate(all_flows[:6], 1):
        display_detailed_rule(flow, i)

    # ---- Summary ----
    display_summary(all_flows)

    # ---- Active vs Unused ----
    display_active_vs_unused(all_flows)

    # ---- Save Report ----
    save_report(all_flows, switches)


def run_dynamic_monitor(interval=5):
    """
    Continuously refresh flow table display.
    Clears screen and updates every `interval` seconds.
    """
    print_header("DYNAMIC FLOW MONITOR")
    print(f"  Refresh interval : {interval} seconds")
    print(f"  Press Ctrl+C to stop\n")
    time.sleep(2)

    iteration = 0

    try:
        while True:
            # Clear terminal
            os.system('clear' if os.name != 'nt' else 'cls')

            iteration += 1
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            print_header(f"DYNAMIC FLOW MONITOR  -  Update #{iteration}")
            print(C(f"  Time    : {ts}", Colors.CYAN))
            print(C(f"  Refresh : every {interval}s  |  Ctrl+C to stop", Colors.BLUE))

            # Discover and get flows
            switches  = get_switches()

            if not switches:
                print(C(
                    "\n  No switches found! "
                    "Start Mininet in another terminal:\n"
                    "    sudo python3 topology.py",
                    Colors.RED
                ))
            else:
                print(C(
                    f"\n  Switches: {switches}",
                    Colors.GREEN
                ))

                all_flows = get_all_flows(switches)

                # Per-switch tables
                for sw in switches:
                    sw_flows = [f for f in all_flows if f['switch'] == sw]
                    display_flow_table(sw, sw_flows)

                # Summary
                display_summary(all_flows)

                # Active vs unused
                display_active_vs_unused(all_flows)

            # Wait
            print(C(
                f"\n  Next refresh in {interval} seconds...",
                Colors.BLUE
            ))
            time.sleep(interval)

    except KeyboardInterrupt:
        print(C(
            "\n\n  Monitoring stopped.",
            Colors.YELLOW
        ))


def run_quick_dump():
    """Just show raw flow table output from ovs-ofctl"""
    switches = get_switches()

    if not switches:
        print(C("No switches found!", Colors.RED))
        return

    for sw in switches:
        print(f"\n{'='*60}")
        print(C(f"RAW FLOW TABLE: {sw}", Colors.BOLD + Colors.WHITE))
        print('='*60)

        result = subprocess.run(
            ['sudo', 'ovs-ofctl', '-O', 'OpenFlow13',
             'dump-flows', sw],
            capture_output=True,
            text=True
        )

        if result.stdout.strip():
            print(result.stdout)
        else:
            print(C("  (empty - no flows)", Colors.YELLOW))

        if result.stderr.strip():
            print(C(f"  stderr: {result.stderr}", Colors.RED))


def run_per_switch_menu(switches, all_flows):
    """Interactive per-switch inspection"""
    print_section("Per-Switch Inspector")

    for i, sw in enumerate(switches, 1):
        count = len([f for f in all_flows if f['switch'] == sw])
        print(f"  {C(str(i), Colors.CYAN)}  {sw}  ({count} flows)")

    print(f"  {C('b', Colors.CYAN)}  Back to main menu")

    choice = input("\n  Select switch: ").strip().lower()

    if choice == 'b':
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(switches):
            sw = switches[idx]
            sw_flows = [f for f in all_flows if f['switch'] == sw]

            display_flow_table(sw, sw_flows)

            if sw_flows:
                show_detail = input(
                    "\n  Show detailed view of a flow? "
                    "(enter flow # or 'n'): "
                ).strip()

                if show_detail.isdigit():
                    idx2 = int(show_detail) - 1
                    if 0 <= idx2 < len(sw_flows):
                        display_detailed_rule(sw_flows[idx2], idx2 + 1)
    except (ValueError, IndexError):
        print(C("  Invalid selection", Colors.RED))


# ============================================================
# MAIN MENU
# ============================================================

def main():
    """Main interactive menu"""

    while True:
        print_header("MULTI-SWITCH FLOW TABLE ANALYZER")
        print(C("  SDN Flow Analysis Tool  |  POX + OVS + OpenFlow 1.3\n",
                Colors.BLUE))

        print(C("  SELECT MODE:", Colors.BOLD))
        print(f"  {C('1', Colors.CYAN)}  Single analysis     (snapshot of current state)")
        print(f"  {C('2', Colors.CYAN)}  Dynamic monitor     (auto-refresh display)")
        print(f"  {C('3', Colors.CYAN)}  Quick dump          (raw ovs-ofctl output)")
        print(f"  {C('4', Colors.CYAN)}  Per-switch inspect  (choose one switch)")
        print(f"  {C('5', Colors.CYAN)}  Check OVS status    (verify setup)")
        print(f"  {C('q', Colors.CYAN)}  Quit\n")

        choice = input(C("  Enter choice: ", Colors.WHITE)).strip().lower()

        # ---- Single Analysis ----
        if choice == '1':
            run_single_analysis()
            input(C("\n  Press Enter to return to menu...", Colors.BLUE))

        # ---- Dynamic Monitor ----
        elif choice == '2':
            try:
                raw = input(
                    C("  Refresh interval in seconds [5]: ", Colors.WHITE)
                ).strip()
                interval = int(raw) if raw.isdigit() else 5
            except ValueError:
                interval = 5
            run_dynamic_monitor(interval=interval)

        # ---- Quick Dump ----
        elif choice == '3':
            run_quick_dump()
            input(C("\n  Press Enter to return to menu...", Colors.BLUE))

        # ---- Per Switch ----
        elif choice == '4':
            switches  = get_switches()
            all_flows = get_all_flows(switches) if switches else []
            if not switches:
                print(C("  No switches found!", Colors.RED))
            else:
                run_per_switch_menu(switches, all_flows)
            input(C("\n  Press Enter to return to menu...", Colors.BLUE))

        # ---- Check Status ----
        elif choice == '5':
            print_section("OVS Status Check")

            # Check OVS running
            result = subprocess.run(
                ['sudo', 'ovs-vsctl', 'show'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(C("  [OK] OVS is running", Colors.GREEN))
                print(result.stdout[:500])
            else:
                print(C("  [FAIL] OVS not running", Colors.RED))
                print(C(
                    "  Fix: sudo service openvswitch-switch start",
                    Colors.YELLOW
                ))

            # Check for switches
            switches = get_switches()
            if switches:
                print(C(f"  [OK] Switches found: {switches}", Colors.GREEN))
            else:
                print(C("  [WARN] No switches - start Mininet first", Colors.YELLOW))

            # Check controller port
            result2 = subprocess.run(
                ['sudo', 'netstat', '-tlnp'],
                capture_output=True, text=True
            )
            if '6633' in result2.stdout:
                print(C("  [OK] Controller port 6633 is listening (POX running)", Colors.GREEN))
            else:
                print(C("  [WARN] Port 6633 not detected - start POX controller", Colors.YELLOW))
                print(C(
                    "  Fix: python pox.py log.level --INFO ext.controller",
                    Colors.BLUE
                ))

            input(C("\n  Press Enter to return to menu...", Colors.BLUE))

        # ---- Quit ----
        elif choice == 'q':
            print(C("\n  Goodbye!\n", Colors.CYAN))
            sys.exit(0)

        else:
            print(C("  Invalid choice - try again", Colors.RED))
            time.sleep(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    main()
