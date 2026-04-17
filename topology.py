#!/usr/bin/env python3
"""
Multi-Switch Topology for Flow Table Analyzer
Creates a network with 3 switches and 6 hosts
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import subprocess

def create_topology():
    """
    Creates this topology:
    
    h1 -- s1 -- s2 -- h3
    h2 /    \  / \ h4
            s3
           /  \
          h5   h6
    """
    
    # Create network with Remote Controller (Ryu)
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info("*** Adding Controller\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )
    
    info("*** Adding Switches\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    
    info("*** Adding Hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
    
    info("*** Adding Links\n")
    # Hosts to switches
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s2, bw=10)
    net.addLink(h4, s2, bw=10)
    net.addLink(h5, s3, bw=10)
    net.addLink(h6, s3, bw=10)
    
    # Switch to switch links
    net.addLink(s1, s2, bw=100)
    net.addLink(s1, s3, bw=100)
    net.addLink(s2, s3, bw=100)
    
    info("*** Starting Network\n")
    net.start()
    
    # Set OpenFlow version
    for switch in [s1, s2, s3]:
        switch.cmd('ovs-vsctl set bridge {} protocols=OpenFlow13'.format(switch.name))
    
    info("*** Waiting for controller connection\n")
    time.sleep(3)
    
    info("*** Network Ready!\n")
    info("*** Switches: s1, s2, s3\n")
    info("*** Hosts: h1(10.0.0.1), h2(10.0.0.2), h3(10.0.0.3)\n")
    info("***        h4(10.0.0.4), h5(10.0.0.5), h6(10.0.0.6)\n")
    
    return net

def run():
    setLogLevel('info')
    net = create_topology()
    
    info("\n*** Generating some traffic for flow entries...\n")
    # Generate traffic so flow tables have entries
    net['h1'].cmd('ping -c 3 10.0.0.3 &')
    net['h2'].cmd('ping -c 3 10.0.0.4 &')
    net['h5'].cmd('ping -c 3 10.0.0.6 &')
    time.sleep(5)
    
    info("\n*** Opening CLI - type 'exit' when done\n")
    CLI(net)
    
    net.stop()

if __name__ == '__main__':
    run()
