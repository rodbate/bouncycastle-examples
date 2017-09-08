package delaytask;


import java.util.LinkedList;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;


public class TimerTaskList extends LinkedList<TimerTask> implements Delayed {


    private final AtomicLong expirationMillis = new AtomicLong(-1L);


    public boolean setExpirationMs(long expireTimeMs){
        return this.expirationMillis.getAndSet(expireTimeMs) != expireTimeMs;
    }

    public long getExpirationMillis() {
        return expirationMillis.get();
    }

    @Override
    public int compareTo(Delayed o) {

        long thisExpireMs = this.getExpirationMillis();
        long thatExpireMs = ((TimerTaskList)o).getExpirationMillis();
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
        return unit.convert(Math.max(expirationMillis.get() - TimeUtils.hiResNow(), 0), TimeUnit.MILLISECONDS);
    }
}
