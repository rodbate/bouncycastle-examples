package delaytask;

import java.util.concurrent.TimeUnit;

public class TimeUtils {

    public static long now() {
        return System.currentTimeMillis();
    }

    public static long hiResNow() {
        long nanos = System.nanoTime();
        return TimeUnit.NANOSECONDS.toMillis(nanos);
    }

}
