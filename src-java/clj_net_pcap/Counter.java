package clj_net_pcap;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 *  This is an experiment.
 *  The primary purpose is to compare this to our counter implementation in Clojure.
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
        lock.lock();
        val = 0;
        lock.unlock();
    }

    public long value() {
        lock.lock();
        long ret = val;
        lock.unlock();
        return ret;
    }

}

