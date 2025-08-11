import java.io.*;

public class FileEncryptorDecryptor {

    public static void main(String[] args) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        try {
            System.out.println("请选择操作：");
            System.out.println("1. 加密文件");
            System.out.println("2. 解密文件");
            System.out.print("输入选项（1/2）：");
            String choice = reader.readLine();

            if ("1".equals(choice)) {
                System.out.print("请输入要加密的文件名：");
                String filename = reader.readLine();
                encryptFile(filename);
            } else if ("2".equals(choice)) {
                System.out.print("请输入要解密的文件名：");
                String filename = reader.readLine();
                System.out.print("请输入密码：");
                String password = reader.readLine();
                decryptFile(filename, password);
            } else {
                System.out.println("无效的选项！");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filename) {
        try {
            String command = "gpg --symmetric --cipher-algo AES256 " + filename;
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});

            StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream());
            StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream());
            outputGobbler.start();
            errorGobbler.start();

            int exitCode = process.waitFor();
            System.out.println("加密完成，退出码：" + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void decryptFile(String filename, String password) {
        try {
            String command = "echo '" + password + "' | gpg --decrypt " + filename;
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});

            StreamGobbler outputGobbler = new StreamGobbler(process.getInputStream());
            StreamGobbler errorGobbler = new StreamGobbler(process.getErrorStream());
            outputGobbler.start();
            errorGobbler.start();

            int exitCode = process.waitFor();
            System.out.println("解密完成，退出码：" + exitCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static class StreamGobbler extends Thread {
        private InputStream is;

        public StreamGobbler(InputStream is) {
            this.is = is;
        }

        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}