package clj_net_pcap;

import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

public class PcapPacketWrapper extends PcapPacket {

    public PcapPacketWrapper (PcapPacket pkt) {
        super(pkt);
    }

    public PcapPacketWrapper (JMemory.Type type) {
        super(type);
    }

    public void free() {
        cleanup();
    }

}

