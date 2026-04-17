#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

def run():
    setLogLevel('info')

    net = Mininet(
        controller=OVSController,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    print("*** Adding controller")
    c0 = net.addController('c0', OVSController)

    print("*** Adding 3 switches")
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    print("*** Adding 6 hosts")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    h5 = net.addHost('h5', ip='10.0.0.5/24')
    h6 = net.addHost('h6', ip='10.0.0.6/24')

    print("*** Adding links")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(h5, s3)
    net.addLink(h6, s3)
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, s3)

    print("*** Starting network")
    net.start()

    print("*** Waiting for network to settle...")
    time.sleep(3)

    print("*** Generating initial traffic...")
    net['h1'].cmd('ping -c 5 10.0.0.3 &')
    net['h2'].cmd('ping -c 5 10.0.0.4 &')
    net['h5'].cmd('ping -c 5 10.0.0.6 &')
    time.sleep(6)

    print("\n*** Network ready! Switches: s1, s2, s3")
    print("*** Hosts: h1(10.0.0.1) h2(10.0.0.2) h3(10.0.0.3)")
    print("***        h4(10.0.0.4) h5(10.0.0.5) h6(10.0.0.6)")
    print("*** Run 'pingall' to generate traffic")
    print("*** Open another terminal and run: sudo python3 analyzer.py\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
