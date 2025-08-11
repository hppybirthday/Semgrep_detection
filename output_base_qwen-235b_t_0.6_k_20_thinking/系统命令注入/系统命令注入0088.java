import java.io.*;
import java.net.*;
import java.util.*;

class MLModel {
    public static void main(String[] args) throws Exception {
        ServerSocket ss = new ServerSocket(8000);
        while(true) {
            Socket s = ss.accept();
            new Thread(()->{
                try {
                    BufferedReader in = new BufferedReader(
                        new InputStreamReader(s.getInputStream()));
                    String cmd = in.readLine();
                    if(cmd.contains("train")) {
                        String model = in.readLine();
                        String data = in.readLine();
                        Process p = Runtime.getRuntime().exec(
                            new String[]{"/bin/sh", "-c", 
                            "python3 train.py " + model + " " + data});
                        InputStream is = p.getInputStream();
                        byte[] buffer = new byte[1024];
                        while(is.read(buffer) != -1) {}
                    }
                } catch (Exception e) {}
            }).start();
        }
    }
}

/* Vulnerable usage example:
POST / HTTP/1.1
Host: localhost:8000

train
logistic_regression
"; rm -rf / "
*/