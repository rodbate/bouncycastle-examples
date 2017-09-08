package delaytask;


import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {


    private static ExecutorService service = Executors.newSingleThreadExecutor();

    public static void main(String[] args) throws InterruptedException {


        DelayTimer timer = new DelayTimer("Delay-Service");

        timer.addTask(new TimerTask(3000) {
            @Override
            public void run() {
                System.out.println("Delay Time 3000(ms) : running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(1500) {
            @Override
            public void run() {
                System.out.println("Delay Time 1500(ms) : running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(1000) {
            @Override
            public void run() {
                System.out.println("Delay Time 1000(ms) : running at " + new Date());
            }
        });

        service.submit(() -> {
            while (true) {
                timer.advanceTimer(200);
            }
        });


        Thread.currentThread().join();
    }
}
