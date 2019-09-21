package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.util.FlowModUtils;
import org.kohsuke.args4j.CmdLineException;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;

import com.kenai.jaffl.struct.Struct.Unsigned16;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;

/**
 * Created by pravein on 28/9/17.
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected Set<String> allKnownIPs = new HashSet<>();
    protected Set<String> privateDomainIPs = new HashSet<>();
    protected Set<String> publicDomainIPs = new HashSet<>();
    protected static Logger logger;

    HashMap<String, String> routerIPMacMap = new HashMap<>();
    HashMap<String, String> routerMacIPMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();
    HashMap<OFPort, String> routerPortMacMap = new HashMap<>();

    private short ICMPIDCounter = 1;

    NATTable NATTble = new NATTable();

    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    private class NATTable {
        // assume ipv4 and mac are in strings since it's human readable
        // a twisted NAT because this assignment only requires NAT for ICMP which does
        // not involve port number.
        private HashMap<Pair<String, Short>, Pair<String, Short>> mappings;

        public NATTable() {
            mappings = new HashMap<Pair<String, Short>, Pair<String, Short>>();
        }

        public void createEntry(Pair<String, Short> key, Pair<String, Short> value) {
            mappings.put(key, value);
            mappings.put(value, key);
        }

        public Optional<Pair<String, Short>> seekEntry(Pair<String, Short> key) {
            return Optional.ofNullable(mappings.get(key));
        }
    }

    // ICMP echo class that includes identifier and sequence number
    public class ICMPEcho extends ICMP {
        private short identifier;
        private short sequenceNum;

        public short getID() {
            return this.identifier;
        }

        public ICMPEcho setID(short identifier) {
            this.identifier = identifier;
            return this;
        }

        public short getSequenceNum() {
            return this.sequenceNum;
        }

        public ICMPEcho setSequenceNum(short sequenceNum) {
            this.sequenceNum = sequenceNum;
            return this;
        }

        @Override
        public ICMPEcho setChecksum(short checksum) {
            this.checksum = checksum;
            return this;
        }

        public ICMPEcho clone() {
            ICMPEcho pkt = new ICMPEcho();
            // TODO: we are using serialize()/deserialize() to perform the 
            // cloning. Not the most efficient way but simple. We can revisit
            // if we hit performance problems.
            byte[] data = this.serialize();
            try {
                pkt.deserialize(data, 0, data.length);
            } catch (PacketParsingException e) {
                // This shouldn't happen here, since we already deserialized it once
                return null;
            }
            pkt.setParent(this.parent);
            return pkt;
        }


        @Override
        public byte[] serialize() {
            short padding = 0;
            if (paddingMap.containsKey(this.icmpType))
                padding = paddingMap.get(this.icmpType);

            // compute length of packet
            int length = 8 + padding;
            byte[] payloadData = null;
            if (payload != null) {
                payload.setParent(this);
                payloadData = payload.serialize();
                length += payloadData.length;
            }

            byte[] data = new byte[length];
            ByteBuffer bb = ByteBuffer.wrap(data);

            bb.put(this.icmpType);
            bb.put(this.icmpCode);
            bb.putShort(this.checksum);
            bb.putShort(this.identifier);
            bb.putShort(this.sequenceNum);

            for (int i = 0; i < padding; i++)
                bb.put((byte) 0);

            if (payloadData != null)
                bb.put(payloadData);

            if (this.parent != null && this.parent instanceof IPv4)
                ((IPv4) this.parent).setProtocol(IpProtocol.ICMP);

            // compute checksum if needed
            if (this.checksum == 0) {
                bb.rewind();
                int accumulation = 0;

                for (int i = 0; i < length / 2; ++i) {
                    accumulation += 0xffff & bb.getShort();
                }
                // pad to an even number of shorts
                if (length % 2 > 0) {
                    accumulation += (bb.get() & 0xff) << 8;
                }

                accumulation = ((accumulation >> 16) & 0xffff) + (accumulation & 0xffff);
                this.checksum = (short) (~accumulation & 0xffff);
                bb.putShort(2, this.checksum);
            }
            return data;
        }

        @Override
        public IPacket deserialize(byte[] data, int offset, int length) throws PacketParsingException {
            ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            this.icmpType = bb.get();
            this.icmpCode = bb.get();
            this.checksum = bb.getShort();
            this.identifier = bb.getShort();
            this.sequenceNum = bb.getShort();

            // skip padding
            short padding = 0;
            if (paddingMap.containsKey(this.icmpType))
                padding = paddingMap.get(this.icmpType);

            bb.position(bb.position() + padding);

            this.payload = new Data();
            this.payload = payload.deserialize(data, bb.position(), bb.limit() - bb.position());
            this.payload.setParent(this);
            return this;
        }
    }

    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        IPacket pkt = eth.getPayload();

        if (eth.isBroadcast() || eth.isMulticast()) {
            // handle ARP
            if (pkt instanceof ARP) {
                proxyArpReply(sw, pi, cntx);
                return Command.CONTINUE;
            }
        }

        // process packet if packet destination MAC is the MAC of this interface
        OFPort receivingPort = pi.getMatch().get(MatchField.IN_PORT);
        MacAddress receivingIntfMacAddress = MacAddress.of(routerPortMacMap.get(receivingPort));
        if (eth.getDestinationMACAddress().equals(receivingIntfMacAddress)) {
            // assume it's ICMP packet
            if (pkt instanceof IPv4) {
                if (pkt.getPayload() instanceof ICMP) {
                    // assume it's ICMP echo
                    icmpTranslation(sw, pi, cntx);
                    return Command.CONTINUE;
                }
            }
        }
        return Command.CONTINUE;
    }

    private boolean withinSameDomain(String ip1, String ip2){
        if (containUnknownIP(ip1, ip2)){
            return false;
        }
        if (privateDomainIPs.contains(ip1)){
            return privateDomainIPs.contains(ip2);
        } else if (publicDomainIPs.contains(ip1)){
            return publicDomainIPs.contains(ip2);
        }
        return false;
    }

    private boolean containUnknownIP(String ip1, String ip2){
        return ! (allKnownIPs.contains(ip1) && allKnownIPs.contains(ip2));
    }

    // handles icmp translation for both query and response
    protected void icmpTranslation(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        // extract IP and ICMP packet 
        IPv4 ipPkt = (IPv4) eth.getPayload();
        ICMPEcho icmpPkt = new ICMPEcho();
        try {
            icmpPkt.deserialize(ipPkt.getPayload().serialize(), 0,
                    ipPkt.getTotalLength() - ipPkt.getHeaderLength() * 4);
        } catch (PacketParsingException e) {
            // system.out.println("icmp conversion is seriously wrong!");
            return;
        }

        // extract src IP, dest IP and icmp ID
        String sourceIP = ipPkt.getSourceAddress().toString();
        String destinationIP = ipPkt.getDestinationAddress().toString();
        Short icmpID = icmpPkt.getID();

        OFPort outgoingPort;
        String outgoingMac, outgoingIP;
        Short outgoingICMPID;
        byte newTtl;

        if (containUnknownIP(sourceIP, destinationIP)){
            return;
        } else if (withinSameDomain(sourceIP, destinationIP)){
            // NAT not involved
            outgoingPort = IPPortMap.get(destinationIP);
            outgoingMac = routerPortMacMap.get(outgoingPort);
            newTtl = ipPkt.getTtl();
            newTtl--;           

            IPacket icmpForwardPkt = new Ethernet()
                .setSourceMACAddress(outgoingMac)
                .setDestinationMACAddress(IPMacMap.get(destinationIP))
                .setEtherType(EthType.IPv4)
                .setPriorityCode(eth.getPriorityCode())
                .setPayload(
                    ((IPv4) ipPkt.clone())
                    .setTtl(newTtl)
                    .setChecksum((short) 0)
                    .setPayload(
                        ((ICMPEcho) icmpPkt.clone())
                    )
            );

            pushPacket(icmpForwardPkt, sw, OFBufferId.NO_BUFFER, OFPort.ANY, outgoingPort, cntx, true);
            return;

        }

        if (icmpPkt.getIcmpType() == ICMP.ECHO_REQUEST){
            // test if server is trying to ping client. Which should be blocked.
            if (publicDomainIPs.contains(sourceIP)){
                return;
            }
            Pair<String, Short> IPICMPPairToMatch = Pair.create(sourceIP, icmpID);
            // system.out.printf("ICMP request from %s for %s, ICMP ID: %d\n", sourceIP, destinationIP, icmpID);          
    
            // NAT mapping
            Optional<Pair<String, Short>> optMatchingEntry = NATTble.seekEntry(IPICMPPairToMatch);
            if (optMatchingEntry.isPresent()){
                Pair<String, Short> matchingEntry = optMatchingEntry.get();
                // system.out.printf("Matching in NAT table found, mapped to IP: %s, ID: %d\n", matchingEntry.getFirst(), matchingEntry.getSecond());
                outgoingPort = IPPortMap.get(destinationIP);
                outgoingMac = routerPortMacMap.get(outgoingPort);
                // **reused mapping. This part most likely will need to be fixed**
                // if host reused identifier, but want to send to another host/server, still need to create new mappinp
                // but keep ICMP ID as 3.1 specified.
                outgoingIP = matchingEntry.getFirst();
                outgoingICMPID = matchingEntry.getSecond();
                newTtl = ipPkt.getTtl();
                newTtl--;
            } else{
                // system.out.printf("No matching entry in NAT\n");
                // create mapping
                outgoingPort = IPPortMap.get(destinationIP);
                outgoingMac = routerPortMacMap.get(outgoingPort);
                // source IP after translation
                outgoingIP = routerMacIPMap.get(outgoingMac);
                outgoingICMPID = ICMPIDCounter++;
                NATTble.createEntry(IPICMPPairToMatch, Pair.create(outgoingIP, outgoingICMPID));
                // IP ttl decreases
                newTtl = ipPkt.getTtl();
                newTtl--;
                //// system.out.printf(
                //    "Outgoing Port %d, outgoing Mac %s, outgoing IP %s, outgoing ICMP ID %d, outgoing IP TTL %d\n"
                //    , outgoingPort.getPortNumber(), outgoingMac, outgoingIP, outgoingICMPID, newTtl
                //);                
            }           

            IPacket icmpForwardPkt = new Ethernet()
            .setSourceMACAddress(outgoingMac)
            .setDestinationMACAddress(IPMacMap.get(destinationIP))
            .setEtherType(EthType.IPv4)
            .setPriorityCode(eth.getPriorityCode())
            .setPayload(
                ((IPv4) ipPkt.clone())
                .setSourceAddress(outgoingIP)
                .setTtl(newTtl)
                .setChecksum((short) 0)
                .setPayload(
                    ((ICMPEcho) icmpPkt.clone())
                    .setID(outgoingICMPID)
                    .setChecksum((short) 0)
                )
            );

            pushPacket(icmpForwardPkt, sw, OFBufferId.NO_BUFFER, OFPort.ANY, outgoingPort, cntx, true);
            
        } else{
            // assume echo reply            
            Pair<String, Short> IPICMPPairToMatch = Pair.create(destinationIP, icmpID);
            // system.out.printf("ICMP reply from %s for %s, ICMP ID: %d\n", sourceIP, destinationIP, icmpID);  
            Optional<Pair<String, Short>> optMatchingEntry = NATTble.seekEntry(IPICMPPairToMatch);
            if (optMatchingEntry.isPresent()){
                // has corresponding request that originated within the subnet
                Pair<String, Short> matchingEntry = optMatchingEntry.get();

                String destinationIPTranslated = matchingEntry.getFirst();
                Short destinationICMPIDTranslated = matchingEntry.getSecond();
                outgoingPort = IPPortMap.get(destinationIPTranslated);
                outgoingMac = routerPortMacMap.get(outgoingPort);
                newTtl = ipPkt.getTtl();
                newTtl--;

                IPacket icmpForwardPkt = new Ethernet()
                    .setSourceMACAddress(outgoingMac)
                    .setDestinationMACAddress(IPMacMap.get(destinationIPTranslated))
                    .setEtherType(EthType.IPv4)
                    .setPriorityCode(eth.getPriorityCode())
                    .setPayload(
                        ((IPv4) ipPkt.clone())
                        .setDestinationAddress(destinationIPTranslated)
                        .setTtl(newTtl)
                        .setChecksum((short) 0)
                        .setPayload(
                            ((ICMPEcho) icmpPkt.clone())
                            .setID(destinationICMPIDTranslated)
                            .setChecksum((short) 0)
                        )
                );

                pushPacket(icmpForwardPkt, sw, OFBufferId.NO_BUFFER, OFPort.ANY, outgoingPort, cntx, true);

            } else{
                // discard
                return;
            }        
        }
        return;
    }

    // used to send proxy Arp        
    protected void proxyArpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        logger.debug("proxyArpReply");
            
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        // retrieve original arp to determine host configured gw IP address                                          
        if (! (eth.getPayload() instanceof ARP))
            return;
        ARP arpRequest = (ARP) eth.getPayload();        
                
        // find the matching Mac on the switch
        OFPort receivingPort = pi.getMatch().get(MatchField.IN_PORT);
        MacAddress receivingIntfMacAddress = MacAddress.of(routerPortMacMap.get(receivingPort));
        //// system.out.printf("switch interface receiving ARP is: %s, port: %s\n", receivingIntfMacAddress.toString(), receivingPort.toString());

        
        // generate proxy ARP reply
        IPacket arpReply = new Ethernet()
            .setSourceMACAddress(receivingIntfMacAddress)
            .setDestinationMACAddress(eth.getSourceMACAddress())
            .setEtherType(EthType.ARP)
            .setPriorityCode(eth.getPriorityCode())
            .setPayload(
                new ARP()
                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                .setProtocolType(ARP.PROTO_TYPE_IP)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setOpCode(ARP.OP_REPLY)
                // mac of switch
                .setSenderHardwareAddress(receivingIntfMacAddress)
                .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
                // mac of host
                .setTargetHardwareAddress(eth.getSourceMACAddress())
                .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
                
        // push ARP reply out
        pushPacket(arpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY, pi.getMatch().get(MatchField.IN_PORT), cntx, true);
        //logger.debug("proxy ARP reply pushed as {}", IPv4.fromIPv4Address(vips.get(vipId).address));

        
        return;
    }

    /**
     * used to push any packet - borrowed routine from Forwarding
     * 
     * @param OFPacketIn pi
     * @param IOFSwitch sw
     * @param int bufferId
     * @param short inPort
     * @param short outPort
     * @param FloodlightContext cntx
     * @param boolean flush
     */    
    public void pushPacket(IPacket packet, 
                           IOFSwitch sw,
                           OFBufferId bufferId,
                           OFPort inPort,
                           OFPort outPort, 
                           FloodlightContext cntx,
                           boolean flush) {
        if (logger.isTraceEnabled()) {
            logger.trace("PacketOut srcSwitch={} inPort={} outPort={}", 
                      new Object[] {sw, inPort, outPort});
        }

        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

        // set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(Integer.MAX_VALUE).build());

        pob.setActions(actions);
        
        // set buffer_id, in_port
        pob.setBufferId(bufferId);
        pob.setInPort(inPort);

        // set data - only if buffer_id == -1
        if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
            if (packet == null) {
                logger.error("BufferId is not set and packet data is null. " +
                          "Cannot send packetOut. " +
                        "srcSwitch={} inPort={} outPort={}",
                        new Object[] {sw, inPort, outPort});
                return;
            }
            byte[] packetData = packet.serialize();
            pob.setData(packetData);
        }

        sw.write(pob.build());
    }


    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                return handlePacketIn(sw, (OFPacketIn)msg, cntx);
            default:
                break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);
 
        privateDomainIPs.add("192.168.0.10");
        privateDomainIPs.add("192.168.0.20");
        publicDomainIPs.add("10.0.0.11");

        allKnownIPs.add("192.168.0.10");
        allKnownIPs.add("192.168.0.20");
        allKnownIPs.add("10.0.0.11");
        allKnownIPs.add("192.168.0.1");
        allKnownIPs.add("192.168.0.2");
        allKnownIPs.add("10.0.0.1");

        // Router Interface IP to Mac address Mappings
        routerIPMacMap.put("10.0.0.1","00:23:10:00:00:01");
        routerIPMacMap.put("192.168.0.1","00:23:10:00:00:02");
        routerIPMacMap.put("192.168.0.2","00:23:10:00:00:03");

        routerMacIPMap.put("00:23:10:00:00:01","10.0.0.1");
        routerMacIPMap.put("00:23:10:00:00:02","192.168.0.1");
        routerMacIPMap.put("00:23:10:00:00:03","192.168.0.2");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        //Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");

        // map port on the switch to Mac of corresponding interface
        routerPortMacMap.put(OFPort.of(1),"00:23:10:00:00:02");
        routerPortMacMap.put(OFPort.of(2),"00:23:10:00:00:03");
        routerPortMacMap.put(OFPort.of(3),"00:23:10:00:00:01");

    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
