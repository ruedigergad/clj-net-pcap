package clj_net_pcap;

import org.jnetpcap.packet.PcapPacket;

public class PcapPacketWrapper extends PcapPacket {

    public PcapPacketWrapper (PcapPacket pkt) {
        super(pkt);
    }

    public void free() {
        cleanup();
    }

}

