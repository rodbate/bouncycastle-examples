package delaytask;


import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DelayTimer {

    private final static int DEFAULT_WHEEL_SIZE = 30;
    private final static int DEFAULT_TICK_TIME_MILLIS = 1;
    private final static int DEFAULT_WORKER_THREAD_NUM = 3;

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
        this(delayTimerName, DEFAULT_WHEEL_SIZE);
    }

    public DelayTimer(String delayTimerName, int wheelSize) {
        this(delayTimerName, wheelSize, DEFAULT_TICK_TIME_MILLIS);
    }

    public DelayTimer(String delayTimerName, int wheelSize, int tickTimeMillis) {
        this(delayTimerName, TimeUtils.hiResNow(), wheelSize, tickTimeMillis, DEFAULT_WORKER_THREAD_NUM);
    }


    public DelayTimer(String delayTimerName, long startTimeMillis, int wheelSize, int tickTimeMillis, int nThreads) {
        this.delayTimerName = delayTimerName;
        this.startTimeMillis = startTimeMillis;
        this.wheelSize = wheelSize;
        this.tickTimeMillis = tickTimeMillis;
        this.executor = new ThreadPoolExecutor(
                nThreads,
                nThreads,
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
