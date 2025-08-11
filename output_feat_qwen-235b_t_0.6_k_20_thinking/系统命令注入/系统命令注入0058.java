import java.io.*;
import java.net.*;
import java.util.*;

class DataCleaner {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8080);
        while (true) {
            Socket s = ss.accept();
            new Thread(() -> {
                try {
                    BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                    String line;
                    while ((line = in.readLine()) != null) {
                        if (line.startsWith("cmd_")) {
                            String cmd = line.substring(4);
                            Process p = Runtime.getRuntime().exec(
                                new String[]{"/bin/sh", "-c", "cat /tmp/data | grep '" + cmd + "'"}
                            );
                            BufferedReader br = new BufferedReader(
                                new InputStreamReader(p.getInputStream())
                            );
                            String out;
                            while ((out = br.readLine()) != null) {
                                System.out.println(out);
                            }
                        }
                    }
                } catch (Exception e) {}
            }).start();
        }
    }
}