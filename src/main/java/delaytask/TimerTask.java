package delaytask;


import java.util.concurrent.atomic.AtomicBoolean;


public abstract class TimerTask implements Runnable {

    private final AtomicBoolean cancel = new AtomicBoolean(false);

    private final long expireTimeMillis;

    public TimerTask(long expireTimeMillis) {
        this.expireTimeMillis = TimeUtils.hiResNow() + expireTimeMillis;
    }

    public void cancel(){
        this.cancel.compareAndSet(false, true);
    }

    public boolean isCancel() {
        return cancel.get();
    }

    public long getExpireTimeMillis() {
        return expireTimeMillis;
    }
}
