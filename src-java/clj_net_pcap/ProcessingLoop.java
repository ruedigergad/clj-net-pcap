package clj_net_pcap;

/**
 *  This is an experiment.
 *  The purpose is primarily to compare the efficiency of the Clojure
 *  way of implementing something like this via loop and recur.
 */
public class ProcessingLoop extends Thread {
    
    private Runnable runnable;
    private boolean running;

    public ProcessingLoop (Runnable runnable) {
        this.runnable = runnable;
    }

    @Override
    public void run () {
        while (running) {
            runnable.run();
        }
    }

    @Override
    public void start () {
        running = true;
        super.start();
    }

    @Override
    public void interrupt () {
        running = false;
        super.interrupt();
    }

}

