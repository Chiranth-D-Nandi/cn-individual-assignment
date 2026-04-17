#!/usr/bin/env python3
"""
Multi-Switch Topology for Flow Table Analyzer
Creates a network with 3 switches and 6 hosts
Uses POX controller (no Ryu required)

Topology:
    h1 -- s1 -- s2 -- h3
    h2 /    \  /  \-- h4
            s3
           /  \
          h5   h6
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import subprocess
import os
import sys

# ============================================================
# TOPOLOGY DEFINITION
# ============================================================

def create_topology():
    """
    Creates multi-switch topology and connects to POX controller
    """

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    # --------------------------------------------------------
    # ADD CONTROLLER (POX runs on 127.0.0.1:6633)
    # --------------------------------------------------------
    info("*** Adding Remote Controller (POX)\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # --------------------------------------------------------
    # ADD SWITCHES
    # --------------------------------------------------------
    info("*** Adding Switches\n")
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')

    # --------------------------------------------------------
    # ADD HOSTS
    # --------------------------------------------------------
    info("*** Adding Hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

    # --------------------------------------------------------
    # ADD LINKS - Hosts to Switches
    # --------------------------------------------------------
    info("*** Adding Host-Switch Links\n")
    net.addLink(h1, s1, bw=10)   # h1 -- s1
    net.addLink(h2, s1, bw=10)   # h2 -- s1
    net.addLink(h3, s2, bw=10)   # h3 -- s2
    net.addLink(h4, s2, bw=10)   # h4 -- s2
    net.addLink(h5, s3, bw=10)   # h5 -- s3
    net.addLink(h6, s3, bw=10)   # h6 -- s3

    # --------------------------------------------------------
    # ADD LINKS - Switch to Switch
    # --------------------------------------------------------
    info("*** Adding Switch-Switch Links\n")
    net.addLink(s1, s2, bw=100)  # s1 -- s2
    net.addLink(s1, s3, bw=100)  # s1 -- s3
    net.addLink(s2, s3, bw=100)  # s2 -- s3

    # --------------------------------------------------------
    # START NETWORK
    # --------------------------------------------------------
    info("*** Starting Network\n")
    net.start()

    # Force OpenFlow 1.3 on all switches
    info("*** Configuring OpenFlow 1.3 on all switches\n")
    for switch in [s1, s2, s3]:
        switch.cmd(
            'ovs-vsctl set bridge {} protocols=OpenFlow13'.format(
                switch.name
            )
        )

    # Set controller for each switch explicitly
    for switch in [s1, s2, s3]:
        switch.cmd(
            'ovs-vsctl set-controller {} tcp:127.0.0.1:6633'.format(
                switch.name
            )
        )

    info("*** Waiting for controller connection (5 seconds)\n")
    time.sleep(5)

    # --------------------------------------------------------
    # VERIFY CONNECTIONS
    # --------------------------------------------------------
    info("\n*** Verifying switch connections:\n")
    for switch in [s1, s2, s3]:
        result = switch.cmd('ovs-vsctl show')
        info(f"  {switch.name}: configured\n")

    # --------------------------------------------------------
    # SHOW NETWORK INFO
    # --------------------------------------------------------
    info("\n*** Network Topology Ready!\n")
    info("*** Switches  : s1, s2, s3\n")
    info("*** Hosts     : h1=10.0.0.1  h2=10.0.0.2\n")
    info("***           : h3=10.0.0.3  h4=10.0.0.4\n")
    info("***           : h5=10.0.0.5  h6=10.0.0.6\n")
    info("*** Controller: 127.0.0.1:6633 (POX)\n")

    return net


# ============================================================
# TRAFFIC GENERATION
# ============================================================

def generate_traffic(net):
    """
    Generate traffic between hosts so flow tables get populated
    """
    info("\n*** Generating traffic to populate flow tables...\n")

    # Ping pairs to create flow entries
    traffic_pairs = [
        ('h1', '10.0.0.3'),   # h1 -> h3  (s1 to s2)
        ('h2', '10.0.0.5'),   # h2 -> h5  (s1 to s3)
        ('h4', '10.0.0.6'),   # h4 -> h6  (s2 to s3)
        ('h1', '10.0.0.6'),   # h1 -> h6  (s1 through s3)
        ('h3', '10.0.0.5'),   # h3 -> h5  (s2 through s3)
    ]

    for src, dst_ip in traffic_pairs:
        info(f"  {src} -> {dst_ip} (3 pings)\n")
        net[src].cmd(f'ping -c 3 -W 1 {dst_ip} &')
        time.sleep(0.5)

    info("*** Waiting for traffic to complete...\n")
    time.sleep(6)
    info("*** Traffic generation done!\n")


# ============================================================
# MAIN RUN FUNCTION
# ============================================================

def run():
    """Main function - creates topology and opens CLI"""

    setLogLevel('info')

    # Clean up any previous mininet state
    info("*** Cleaning up previous Mininet state\n")
    os.system('sudo mn -c 2>/dev/null')
    time.sleep(1)

    # Create topology
    net = create_topology()

    # Generate some traffic
    generate_traffic(net)

    # Show instructions
    info("\n" + "="*60 + "\n")
    info("*** MININET CLI IS READY\n")
    info("*** Useful commands:\n")
    info("***   pingall          - test all host connectivity\n")
    info("***   h1 ping -c 5 10.0.0.3  - specific ping\n")
    info("***   exit             - quit Mininet\n")
    info("="*60 + "\n\n")

    # Open interactive CLI
    CLI(net)

    # Cleanup on exit
    info("*** Stopping network\n")
    net.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':
    run()
