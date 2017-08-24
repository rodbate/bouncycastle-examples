package update;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 *
 * Created by rodbate on 2017/8/24.
 */
public class BufferTLS {


    public static void main(String[] args) {

        ByteBuffer buf = ByteBuffer.allocateDirect(1024);


        int curPos = 0;
        int i = 1;
        while (curPos <= 1024) {
            ByteBuffer slice = buf.slice();
            slice.position(curPos);
            byte[] part = String.format("part %d ", i).getBytes(StandardCharsets.UTF_8);
            if (curPos + part.length > 1024) {
                break;
            }
            slice.put(part, 0, part.length);
            curPos += part.length;
            ++i;
        }
        byte[] b = new byte[curPos - 1];
        buf.get(b);
        System.out.println(curPos);
        System.out.println(new String(b));



    }
}
