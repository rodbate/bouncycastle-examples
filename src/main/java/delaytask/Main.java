package delaytask;


import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {


    private static ExecutorService service = Executors.newSingleThreadExecutor();

    public static void main(String[] args) throws InterruptedException {


        DelayTimer timer = new DelayTimer("Delay-Service");

        timer.addTask(new TimerTask(3000) {
            private Date build = new Date();
            @Override
            public void run() {
                System.out.println("Delay Time 3000(ms) : new at " + build + "  running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(2000) {
            private Date build = new Date();
            @Override
            public void run() {
                System.out.println("Delay Time 2000(ms) : new at " + build + "  running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(1000) {
            private Date build = new Date();
            @Override
            public void run() {
                System.out.println("Delay Time 1000(ms) : new at " + build + "  running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(10000) {
            private Date build = new Date();
            @Override
            public void run() {
                System.out.println("Delay Time 10000(ms) : new at " + build + "  running at " + new Date());
            }
        });

        timer.addTask(new TimerTask(1000 * 60 * 2) {
            private Date build = new Date();
            @Override
            public void run() {
                System.out.println("Delay Time 2(min) : new at " + build + "  running at " + new Date());
            }
        });



        service.submit(() -> {
            while (true) {
                timer.advanceTimer(2000);
            }
        });


        //Thread.currentThread().join();
    }
}
