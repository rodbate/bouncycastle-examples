package bcfipsin100.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Callable;

import org.bouncycastle.util.Strings;

public class Util
{
    public interface BlockingCallable
        extends Callable
    {
        void await() throws InterruptedException;
    }

    public static class Task
        implements Runnable
    {
        private final Callable callable;

        public Task(Callable callable)
        {
            this.callable = callable;
        }

        public void run()
        {
            try
            {
                callable.call();
            }
            catch (Exception e)
            {
                e.printStackTrace(System.err);
                if (e.getCause() != null)
                {
                    e.getCause().printStackTrace(System.err);
                }
            }
        }
    }

    public static void runClientAndServer(BlockingCallable server, BlockingCallable client)
        throws InterruptedException
    {
        new Thread(new Task(server)).start();
        server.await();

        new Thread(new Task(client)).start();
        client.await();
    }

    public static void doClientProtocol(
        Socket sock,
        String text)
        throws IOException
    {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        out.write(Strings.toByteArray(text));
        out.write('!');

        int ch = 0;
        while ((ch = in.read()) != '!')
        {
            System.out.print((char)ch);
        }

        System.out.println((char)ch);
    }

    public static void doServerProtocol(
        Socket sock,
        String text)
        throws IOException
    {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        int ch;
        while ((ch = in.read()) != '!')
        {
            System.out.print((char)ch);
        }

        out.write(Strings.toByteArray(text));
        out.write('!');

        System.out.println((char)ch);
    }
}
