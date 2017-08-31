package mmap;


import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;


public abstract class ServiceThread implements Runnable {

    private static final long DEFAULT_JOIN_TIME_MS = 60 * 1000;

    private volatile boolean isStopped = false;

    private Thread thread;

    private final CountDownLatchReset waitLatch = new CountDownLatchReset(1);

    private AtomicBoolean hasNotified = new AtomicBoolean(false);


    public ServiceThread(boolean isDaemon) {
        this.thread = new Thread(this, getServiceName());
        this.thread.setDaemon(isDaemon);
        this.thread.setPriority(Thread.NORM_PRIORITY);
    }

    public void start() {
        this.thread.start();
    }

    public void shutdown(boolean isInterrupt){
        isStopped = true;

        if (hasNotified.compareAndSet(false, true)) {
            waitLatch.countDown();
        }

        if (isInterrupt) {
            thread.interrupt();
        }

        if (!thread.isDaemon()) {
            try {
                thread.join(getJoinTimeMs());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        System.out.println(String.format("Service Thread [%s] shutdown now", getServiceName()));
    }

    public void markStopped(){
        isStopped = true;
    }

    public void stop(boolean isInterrupt) {
        isStopped = true;

        if (hasNotified.compareAndSet(false, true)) {
            waitLatch.countDown();
        }

        if (isInterrupt) {
            thread.interrupt();
        }
    }

    public void waitForRunning(long interval) {
        if (hasNotified.compareAndSet(true, false)){
            onWaitEnd();
            return;
        }

        waitLatch.reset();

        try {
            waitLatch.wait(interval);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            onWaitEnd();
        }
    }


    public void wakeUp(){
        if (!hasNotified.compareAndSet(false, true)){
            return;
        }
        try {
            waitLatch.countDown();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean isStopped() {
        return isStopped;
    }

    protected long getJoinTimeMs() {
        return DEFAULT_JOIN_TIME_MS;
    }


    protected abstract void onWaitEnd();

    public abstract String getServiceName();


    static class CountDownLatchReset {

        private static final class Sync extends AbstractQueuedSynchronizer {
            private static final long serialVersionUID = -1L;

            private final int startCount;

            Sync(int count) {
                startCount = count;
                setState(count);
            }

            int getCount() {
                return getState();
            }

            void reset() {
                setState(startCount);
            }

            protected int tryAcquireShared(int acquires) {
                return (getState() == 0) ? 1 : -1;
            }

            protected boolean tryReleaseShared(int releases) {
                for (;;) {
                    int c = getState();
                    if (c == 0)
                        return false;
                    int nextc = c-1;
                    if (compareAndSetState(c, nextc))
                        return nextc == 0;
                }
            }
        }

        private final CountDownLatchReset.Sync sync;


        public CountDownLatchReset(int count) {
            if (count < 0) throw new IllegalArgumentException("count < 0");
            this.sync = new CountDownLatchReset.Sync(count);
        }


        public void await() throws InterruptedException {
            sync.acquireSharedInterruptibly(1);
        }


        public boolean await(long timeout, TimeUnit unit)
                throws InterruptedException {
            return sync.tryAcquireSharedNanos(1, unit.toNanos(timeout));
        }


        public void countDown() {
            sync.releaseShared(1);
        }


        public long getCount() {
            return sync.getCount();
        }

        public void reset() {
            sync.reset();
        }

        public String toString() {
            return super.toString() + "[Count = " + sync.getCount() + "]";
        }
    }
}
