package clj_net_pcap;

/**
 *  This is an experiment.
 *  The primary purpose is to compare this to the Clojure counter implementation.
 */
public class Counter {

    private long val = 0;

    public void inc() {
        val++;
    }

    public void reset() {
        val = 0;
    }

    public long value() {
        return val;
    }

}

