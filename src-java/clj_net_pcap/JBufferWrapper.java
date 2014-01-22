package clj_net_pcap;

import java.nio.ByteBuffer;
import org.jnetpcap.nio.JBuffer;

public class JBufferWrapper extends JBuffer {

    public JBufferWrapper(ByteBuffer buf) {
        super(buf);
    }

    public void free() {
        cleanup();
    }

}

