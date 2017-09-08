package delaytask;


import java.util.LinkedList;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;


public class TimerTaskList extends LinkedList<TimerTask> implements Delayed {


    private final AtomicLong expirationMillis = new AtomicLong();


    public boolean setExpirationMs(long expireTimeMs){
        return this.expirationMillis.getAndSet(expireTimeMs) != expireTimeMs;
    }

    public long getExpirationMillis() {
        return expirationMillis.get();
    }

    @Override
    public int compareTo(Delayed o) {
        long thisExpireMs = this.getDelay(TimeUnit.NANOSECONDS);
        long thatExpireMs = o.getDelay(TimeUnit.NANOSECONDS);
        if (thisExpireMs - thatExpireMs > 0) {
            return 1;
        } else if (thisExpireMs -thatExpireMs < 0) {
            return -1;
        } else {
            return 0;
        }
    }

    @Override
    public long getDelay(TimeUnit unit) {
        return unit.convert(expirationMillis.get(), TimeUnit.MILLISECONDS);
    }
}
