package delaytask;


import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DelayTimer {

    private final String delayTimerName;
    private final long startTimeMillis;
    private final int wheelSize;
    private final int tickTimeMillis;
    private final ExecutorService executor;
    private final LinkedBlockingQueue<Runnable> taskQueue = new LinkedBlockingQueue<>();
    private final DelayQueue<TimerTaskList> queue = new DelayQueue<>();
    private final TimerWheel timerWheel;
    private final Lock lock = new ReentrantLock();

    public DelayTimer(String delayTimerName) {
        this(delayTimerName, TimeUtils.hiResNow(), 30, 1000);
    }

    public DelayTimer(String delayTimerName, int wheelSize) {
        this(delayTimerName, TimeUtils.hiResNow(), wheelSize, 1000);
    }

    public DelayTimer(String delayTimerName, int wheelSize, int tickTimeMillis) {
        this(delayTimerName, TimeUtils.hiResNow(), wheelSize, tickTimeMillis);
    }


    public DelayTimer(String delayTimerName, long startTimeMillis, int wheelSize, int tickTimeMillis) {
        this.delayTimerName = delayTimerName;
        this.startTimeMillis = startTimeMillis;
        this.wheelSize = wheelSize;
        this.tickTimeMillis = tickTimeMillis;
        this.executor = new ThreadPoolExecutor(
                1,
                1,
                60,
                TimeUnit.SECONDS,
                taskQueue,
                new ThreadFactory() {
                    private final AtomicInteger idx = new AtomicInteger(1);
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r);
                        t.setName(delayTimerName + "--" + idx.getAndIncrement());
                        t.setDaemon(false);
                        t.setPriority(Thread.NORM_PRIORITY);
                        return t;
                    }
                }
        );
        this.timerWheel = new TimerWheel(startTimeMillis, tickTimeMillis, wheelSize, queue);
    }


    public void addTask(TimerTask task) {
        lock.lock();
        try {
            addTask0(task);
        } finally {
            lock.unlock();
        }
    }

    private void addTask0 (TimerTask task) {
        if (!timerWheel.add(task)) {
            if (!task.isCancel()) {
                executor.submit(task);
            }
        }
    }

    public boolean advanceTimer(long ts) {
        TimerTaskList taskListOfBucket;
        try {
            taskListOfBucket = queue.poll(ts, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            taskListOfBucket = null;
        }
        if (taskListOfBucket != null) {
            lock.lock();
            try {
                while (taskListOfBucket != null) {
                    timerWheel.advanceTimer(taskListOfBucket.getExpirationMillis());
                    TimerTaskList newList = new TimerTaskList();
                    newList.addAll(taskListOfBucket);
                    taskListOfBucket.clear();
                    newList.forEach(this::addTask0);
                    taskListOfBucket = queue.poll();
                }
            } finally {
                lock.unlock();
            }
            return true;
        }
        return false;
    }

}
