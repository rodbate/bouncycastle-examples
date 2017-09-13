package delaytask;


import java.util.concurrent.DelayQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;


public class TimerWheel {

    private final long startTimeMillis;
    private final int tickTimeMillis;
    private final int wheelSize;
    private long currentTimeMillis;
    private final int intervalMillis;

    private static final AtomicReferenceFieldUpdater<TimerWheel, TimerWheel> parentWheelUpdater =
            AtomicReferenceFieldUpdater.newUpdater(TimerWheel.class, TimerWheel.class, "parentWheel");

    private volatile TimerWheel parentWheel = null;

    private final DelayQueue<TimerTaskList> queue;
    private final TimerTaskList buckets[];

    public TimerWheel(long startTimeMillis, int tickTimeMillis, int wheelSize, DelayQueue<TimerTaskList> queue) {
        this.startTimeMillis = startTimeMillis;
        this.tickTimeMillis = tickTimeMillis;
        this.wheelSize = wheelSize;
        this.queue = queue;
        this.currentTimeMillis = this.startTimeMillis - this.startTimeMillis % this.tickTimeMillis;
        this.intervalMillis = this.tickTimeMillis * this.wheelSize;

        this.buckets = new TimerTaskList[wheelSize];
        for (int i = 0; i < this.buckets.length; i++) {
            this.buckets[i] = new TimerTaskList();
        }
    }

    private void newParentWheel() {
        TimerWheel parentWheel = new TimerWheel(
                currentTimeMillis,
                intervalMillis,
                wheelSize,
                queue
        );
        this.parentWheelUpdater.compareAndSet(this, null, parentWheel);
    }

    public boolean add(TimerTask task) {
        long expireTimeMillis = task.getExpireTimeMillis();

        if (task.isCancel()) {
            return false;
        } else if (expireTimeMillis < currentTimeMillis + tickTimeMillis) {
            //task expire
            return false;
        } else if (expireTimeMillis < currentTimeMillis + intervalMillis) {
            int vidx = (int) (expireTimeMillis / tickTimeMillis);
            TimerTaskList bucket = this.buckets[vidx % this.buckets.length];
            bucket.add(task);

            if (bucket.setExpirationMs(vidx * tickTimeMillis)) {
                queue.offer(bucket);
            }
            return true;
        } else {
            if (parentWheel == null) {
                newParentWheel();
            }
            parentWheel.add(task);
            return true;
        }

    }

    public void advanceTimer(long timeMs) {
        if (timeMs >= currentTimeMillis + tickTimeMillis) {
            this.currentTimeMillis = timeMs - timeMs % tickTimeMillis;
            if (parentWheel != null) {
                parentWheel.advanceTimer(currentTimeMillis);
            }
        }
    }

}
