import java.io.*;
public class FileCrypt {
    public static void main(String[] args) {
        if(args.length < 3) {
            System.out.println("Usage: java FileCrypt <enc|dec> <filename> <key>");
            return;
        }
        try {
            String op = args[0];
            String file = args[1];
            String key = args[2];
            String cmd = "openssl " + (op.equals("enc") ? "enc -aes-256-cbc -in " : "dec -aes-256-cbc -d -in ") + 
                         file + " -out " + file + (op.equals("enc") ? ".enc" : ".dec") + " -pass pass:" + key;
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while((line = br.readLine()) != null) {
                System.out.println(line);
            }
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}