package clj_net_pcap;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 *  This is an experiment.
 *  The primary purpose is to compare this to the Clojure counter implementation.
 */
public class Counter {

    private long val = 0;
    private Lock lock = new ReentrantLock();

    public void inc() {
        /*
         * In the current use case we prefer to miss an increment in favor of performance.
         */
        if (lock.tryLock()) {
            val++;
            lock.unlock();
        }
    }

    public void reset() {
        /*
         * A reset has to allways succeed.
         */
        lock.lock();
        val = 0;
        lock.unlock();
    }

    public long value() {
        /*
         * We prefer to return an invalid value in favor of performance.
         * Invalid values are handled in the calling code.
         */
        long ret = -1;
        if (lock.tryLock()) {
            ret = val;
            lock.unlock();
        }
        return ret;
    }

}

