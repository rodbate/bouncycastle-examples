package delaytask;

import java.util.concurrent.TimeUnit;

public class SystemTime {

    public static long now() {
        return System.currentTimeMillis();
    }

    public static long hiResNow() {
        long nanos = System.nanoTime();
        return TimeUnit.NANOSECONDS.toMillis(nanos);
    }

    public static void main(String[] args) {
        System.out.println(System.currentTimeMillis() + "  " + System.nanoTime());
    }
}
