package clj_net_pcap;

/**
 *  This is an experiment.
 *  The purpose is primarily to compare the efficiency of the Clojure
 *  way of implementing something like this via loop and recur.
 */
public class InfiniteLoop extends Thread {
    
    private Runnable runnable;

    public InfiniteLoop (Runnable runnable) {
        this.runnable = runnable;
    }

    @Override
    public void run () {
        while (true) {
            runnable.run();
        }
    }

}

