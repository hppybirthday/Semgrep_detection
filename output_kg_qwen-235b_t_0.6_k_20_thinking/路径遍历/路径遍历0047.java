import java.io.*;

public class VulnerableFileEncryptor {
    private static final String BASE_DIR = "/safe/files/";

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java VulnerableFileEncryptor [encrypt|decrypt] [file_path]");
            return;
        }

        String operation = args[0];
        String userInput = args[1];

        // 路径遍历漏洞点：直接拼接用户输入
        File file = new File(BASE_DIR + userInput);

        if (!file.exists()) {
            System.out.println("File does not exist: " + file.getAbsolutePath());
            return;
        }

        try {
            if (operation.equals("encrypt")) {
                byte[] data = readFile(file);
                byte[] encrypted = encrypt(data);
                writeFile(new File(file.getAbsolutePath() + ".enc"), encrypted);
                System.out.println("Encrypted to: " + file.getAbsolutePath() + ".enc");
            } else if (operation.equals("decrypt")) {
                byte[] data = readFile(file);
                byte[] decrypted = decrypt(data);
                writeFile(new File(file.getAbsolutePath().replace(".enc", "")), decrypted);
                System.out.println("Decrypted to: " + file.getAbsolutePath().replace(".enc", ""));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static byte[] readFile(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    private static void writeFile(File file, byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(data);
        fos.close();
    }

    private static byte[] encrypt(byte[] data) {
        // 简单异或加密作为示例
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ 0xA5);
        }
        return data;
    }

    private static byte[] decrypt(byte[] data) {
        return encrypt(data); // 对称操作
    }
}