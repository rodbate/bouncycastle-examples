package mmap;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class MMapMain {




    static class MapService extends ServiceThread {

        private List<MappedByteBuffer> bufferList = new ArrayList<>();
        private List<FileChannel> fileChannelList = new ArrayList<>();

        private void initMap(String storePath, int fileSize, int fileNum){
            File dir = new File(storePath);
            if (!dir.exists()) {
                if (!dir.mkdirs()) {
                    return;
                }
            }

            long curTotalSize = 0;
            for (int i = 0; i < fileNum; i++) {
                String fileName = String.format("%020d", curTotalSize);
                try {
                    RandomAccessFile file = new RandomAccessFile(dir.getPath() + "/" + fileName, "rw");
                    FileChannel channel = file.getChannel();
                    MappedByteBuffer byteBuffer =  channel.map(FileChannel.MapMode.READ_WRITE, 0, fileSize);
                    fileChannelList.add(channel);
                    bufferList.add(byteBuffer);
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                curTotalSize += fileSize;
            }

        }

        public MapService(boolean isDaemon) {
            super(isDaemon);
        }

        @Override
        protected void onWaitEnd() {
            //System.out.println("Invoke onWaitEnd method ... ");
        }

        @Override
        public String getServiceName() {
            return getClass().getSimpleName();
        }

        @Override
        public void run() {
            int fileSize = 1024 * 1024 * 1024;
            initMap("D:\\test\\map", fileSize, 10);
            while (!isStopped()) {
                System.out.println("------------ mapped byte buffer size : " + bufferList.size());
                for (int i = 0; i < bufferList.size(); i++) {
                    //MappedByteBuffer mappedByteBuffer = bufferList.get(i);
                    //mappedByteBuffer.put("Test map |".getBytes(StandardCharsets.UTF_8));
                    //mappedByteBuffer.force();
                    FileChannel fileChannel = fileChannelList.get(i);
                    try {
                        fileChannel.write(ByteBuffer.wrap("1213 |".getBytes(StandardCharsets.UTF_8)));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                waitForRunning(1000);
            }
        }
    }

    public static void main(String[] args) throws InterruptedException {

        MapService mapService = new MapService(false);
        mapService.start();

        //Thread.sleep(10000);
        //mapService.stop(true);

    }
}
