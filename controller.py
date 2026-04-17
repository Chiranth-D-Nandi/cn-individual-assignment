"""
This controller:
1. Learns MAC addresses per switch
2. Installs OpenFlow flow rules
3. Tracks packet/byte counts
4. Saves flow stats to /tmp/flow_stats.json
"""

# ============================================================
# POX IMPORTS
# ============================================================
from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.recoco import Timer

import json
import time
import os
from datetime import datetime

# POX logger
log = core.getLogger()


# ============================================================
# MAIN CONTROLLER CLASS
# ============================================================

class MultiSwitchController(object):
    """
    POX Controller that manages multiple switches.
    - Learns MAC -> port mappings per switch
    - Installs flow rules for known destinations
    - Floods for unknown destinations
    - Collects and saves flow statistics
    """

    def __init__(self):
        """Initialize controller state"""

        # MAC table: {dpid: {mac_address: port_number}}
        self.mac_to_port = {}

        # Flow statistics: {dpid: [list of flow dicts]}
        self.flow_stats = {}

        # Track all known datapaths (switches)
        self.datapaths = {}

        # Track when flows were installed: {flow_key: timestamp}
        self.flow_install_times = {}

        # Counter for total packets handled
        self.total_packets = 0

        # Listen to POX events
        core.openflow.addListeners(self)

        log.info("="*50)
        log.info("  Multi-Switch Flow Table Controller Started")
        log.info("  Listening on port 6633")
        log.info("="*50)

        # Start periodic stats collection (every 10 seconds)
        Timer(10, self._collect_stats, recurring=True)

        # Start periodic save to file (every 15 seconds)
        Timer(15, self._save_stats_to_file, recurring=True)


    # --------------------------------------------------------
    # EVENT: Switch Connected
    # --------------------------------------------------------

    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects to the controller.
        We store the connection and set up the switch.
        """
        dpid = event.dpid
        connection = event.connection

        log.info(f"Switch connected: DPID={dpidToStr(dpid)}")

        # Store this switch's connection
        self.datapaths[dpid] = connection
        self.mac_to_port[dpid] = {}
        self.flow_stats[dpid]  = []

        # Send table-miss flow: forward all unknown packets to controller
        # This is the default rule (lowest priority)
        self._install_table_miss(connection)

        log.info(f"Switch {dpidToStr(dpid)}: table-miss flow installed")


    def _handle_ConnectionDown(self, event):
        """Called when a switch disconnects"""
        dpid = event.dpid
        log.warning(f"Switch disconnected: DPID={dpidToStr(dpid)}")

        # Remove from our tables
        if dpid in self.datapaths:
            del self.datapaths[dpid]
        if dpid in self.mac_to_port:
            del self.mac_to_port[dpid]


    # --------------------------------------------------------
    # EVENT: Packet Received (PacketIn)
    # --------------------------------------------------------

    def _handle_PacketIn(self, event):
        """
        Called when switch sends packet to controller.
        This happens when:
        1. No flow rule matches the packet
        2. The table-miss rule sends it to controller

        We:
        1. Learn the source MAC -> port
        2. Look up destination MAC
        3. Install a flow rule if destination is known
        4. Forward the packet
        """
        self.total_packets += 1

        packet_data = event.parsed
        dpid        = event.dpid
        in_port     = event.port

        # Ignore malformed packets
        if not packet_data.parsed:
            log.warning("Ignoring unparsed packet")
            return

        eth_packet = packet_data

        src_mac = str(eth_packet.src)
        dst_mac = str(eth_packet.dst)

        log.debug(
            f"PacketIn: switch={dpidToStr(dpid)} "
            f"port={in_port} "
            f"src={src_mac} "
            f"dst={dst_mac}"
        )

        # Initialize MAC table for this switch if needed
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        # ---- LEARN source MAC ----
        self.mac_to_port[dpid][src_mac] = in_port
        log.debug(f"  Learned: {src_mac} is on port {in_port} of switch {dpidToStr(dpid)}")

        # ---- LOOK UP destination MAC ----
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            log.debug(f"  Known destination: {dst_mac} -> port {out_port}")

            # Install flow rule for this src->dst pair
            self._install_flow_rule(
                connection=event.connection,
                dpid=dpid,
                in_port=in_port,
                src_mac=src_mac,
                dst_mac=dst_mac,
                out_port=out_port
            )

        else:
            # Destination unknown - flood
            out_port = of.OFPP_FLOOD
            log.debug(f"  Unknown destination: {dst_mac} -> FLOOD")

        # ---- FORWARD the packet ----
        self._send_packet(
            connection=event.connection,
            packet=event.ofp,
            out_port=out_port
        )


    # --------------------------------------------------------
    # FLOW INSTALLATION HELPERS
    # --------------------------------------------------------

    def _install_table_miss(self, connection):
        """
        Install the table-miss flow entry.
        This catches all packets with no matching rule
        and sends them to the controller.
        Priority = 0 (lowest)
        """
        msg = of.ofp_flow_mod()

        # Empty match = match everything
        msg.match = of.ofp_match()

        # Priority 0 = lowest (table miss)
        msg.priority = 0

        # No timeouts (permanent rule)
        msg.idle_timeout = 0
        msg.hard_timeout = 0

        # Action: send to controller
        msg.actions.append(
            of.ofp_action_output(port=of.OFPP_CONTROLLER)
        )

        connection.send(msg)


    def _install_flow_rule(self, connection, dpid,
                           in_port, src_mac, dst_mac, out_port):
        """
        Install a specific flow rule for src->dst communication.
        Priority = 1 (above table-miss)
        Idle timeout = 30s (remove if no traffic for 30 seconds)
        Hard timeout = 120s (remove after 2 minutes regardless)
        """
        msg = of.ofp_flow_mod()

        # Match on: incoming port + source MAC + destination MAC
        msg.match = of.ofp_match(
            in_port=in_port,
            dl_src=EthAddr(src_mac),
            dl_dst=EthAddr(dst_mac)
        )

        # Priority 1 = above table-miss
        msg.priority = 1

        # Timeouts so unused rules expire
        msg.idle_timeout = 30   # Remove if idle for 30 seconds
        msg.hard_timeout = 120  # Remove after 120 seconds always

        # Action: output to discovered port
        msg.actions.append(
            of.ofp_action_output(port=out_port)
        )

        # Send to switch
        connection.send(msg)

        # Record installation time
        flow_key = f"{dpid}_{in_port}_{src_mac}_{dst_mac}"
        self.flow_install_times[flow_key] = time.time()

        log.info(
            f"Flow installed on {dpidToStr(dpid)}: "
            f"port{in_port} {src_mac}->{dst_mac} => port{out_port}"
        )


    def _send_packet(self, connection, packet, out_port):
        """
        Send a packet out a specific port.
        Used to forward the original PacketIn packet.
        """
        msg = of.ofp_packet_out()
        msg.data = packet

        # Add output action
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Set input port
        msg.in_port = packet.in_port

        connection.send(msg)


    # --------------------------------------------------------
    # FLOW STATISTICS COLLECTION
    # --------------------------------------------------------

    def _collect_stats(self):
        """
        Request flow statistics from all connected switches.
        Called every 10 seconds by Timer.
        """
        log.debug(
            f"Collecting stats from {len(self.datapaths)} switches"
        )

        for dpid, connection in self.datapaths.items():
            # Send flow stats request to this switch
            msg = of.ofp_stats_request()
            msg.type = of.OFPST_FLOW
            msg.body = of.ofp_flow_stats_request()
            connection.send(msg)


    def _handle_FlowStatsReceived(self, event):
        """
        Called when switch responds with flow statistics.
        We store the data and save to file.
        """
        dpid  = event.dpid
        stats = event.stats

        log.info(
            f"Stats from switch {dpidToStr(dpid)}: "
            f"{len(stats)} flows"
        )

        flows = []
        for stat in stats:
            flow_info = {
                'dpid'         : dpid,
                'dpid_str'     : dpidToStr(dpid),
                'table_id'     : stat.table_id,
                'priority'     : stat.priority,
                'match'        : self._format_match(stat.match),
                'actions'      : self._format_actions(stat.actions),
                'packet_count' : stat.packet_count,
                'byte_count'   : stat.byte_count,
                'duration_sec' : stat.duration_sec,
                'idle_timeout' : stat.idle_timeout,
                'hard_timeout' : stat.hard_timeout,
                'cookie'       : stat.cookie,
                'timestamp'    : time.time()
            }
            flows.append(flow_info)

        self.flow_stats[dpid] = flows


    def _format_match(self, match):
        """Convert ofp_match object to readable string"""
        fields = []

        if match.in_port:
            fields.append(f"in_port={match.in_port}")

        if match.dl_src:
            fields.append(f"dl_src={match.dl_src}")

        if match.dl_dst:
            fields.append(f"dl_dst={match.dl_dst}")

        if match.nw_src:
            fields.append(f"nw_src={match.nw_src}")

        if match.nw_dst:
            fields.append(f"nw_dst={match.nw_dst}")

        if match.dl_type:
            fields.append(f"dl_type={hex(match.dl_type)}")

        if not fields:
            return "any"

        return ", ".join(fields)


    def _format_actions(self, actions):
        """Convert list of actions to readable string"""
        if not actions:
            return "drop"

        result = []
        for action in actions:
            if isinstance(action, of.ofp_action_output):
                port = action.port
                if port == of.OFPP_CONTROLLER:
                    result.append("CONTROLLER")
                elif port == of.OFPP_FLOOD:
                    result.append("FLOOD")
                elif port == of.OFPP_ALL:
                    result.append("ALL")
                else:
                    result.append(f"output:{port}")
            else:
                result.append(str(type(action).__name__))

        return ", ".join(result)


    # --------------------------------------------------------
    # SAVE STATS TO FILE
    # --------------------------------------------------------

    def _save_stats_to_file(self):
        """
        Save all flow statistics to /tmp/flow_stats.json
        The analyzer.py reads this file.
        """
        try:
            all_flows = []
            for dpid, flows in self.flow_stats.items():
                all_flows.extend(flows)

            data = {
                'timestamp'   : datetime.now().isoformat(),
                'total_flows' : len(all_flows),
                'switches'    : [dpidToStr(d) for d in self.datapaths.keys()],
                'flows'       : all_flows
            }

            # Write to temp file first, then rename (atomic write)
            tmp_file = '/tmp/flow_stats.tmp'
            out_file = '/tmp/flow_stats.json'

            with open(tmp_file, 'w') as f:
                json.dump(data, f, indent=2)

            os.replace(tmp_file, out_file)

            log.debug(
                f"Stats saved to {out_file} "
                f"({len(all_flows)} flows)"
            )

        except Exception as e:
            log.error(f"Error saving stats: {e}")


# ============================================================
# POX LAUNCH FUNCTION
# ============================================================

def launch():
    """
    POX calls this function when the component is loaded.
    This is the entry point for: python pox.py ext.controller
    """
    log.info("Launching Multi-Switch Flow Table Controller...")
    core.registerNew(MultiSwitchController)

    # Also register for flow stats events
    core.openflow.addListenerByName(
        "FlowStatsReceived",
        core.MultiSwitchController._handle_FlowStatsReceived
    )
