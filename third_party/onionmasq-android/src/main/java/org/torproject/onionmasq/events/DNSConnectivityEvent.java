package org.torproject.onionmasq.events;

import java.net.InetAddress;

public class DNSConnectivityEvent extends OnionmasqEvent {

    public boolean hasEnforcedPrivateDNS;
    public String privateDNSHostname = "";
    public InetAddress[] privateDNSServers = new InetAddress[0];

    public DNSConnectivityEvent(boolean hasPrivateDNS, String privateDNSHostname, InetAddress[] privateDNSServers) {
        this.hasEnforcedPrivateDNS = hasPrivateDNS && privateDNSHostname != null;
        this.privateDNSHostname = privateDNSHostname;
        this.privateDNSServers = privateDNSServers;
    }
}
