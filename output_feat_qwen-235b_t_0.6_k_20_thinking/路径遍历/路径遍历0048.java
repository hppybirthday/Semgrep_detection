import java.io.*;
import java.util.Scanner;

public class FileCrypt {
    private static final String BASE_DIR = "secure_storage/";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Operation (encrypt/decrypt): ");
        String op = scanner.nextLine();
        System.out.print("Filename: ");
        String filename = scanner.nextLine();
        System.out.print("Key (16 chars): ");
        String key = scanner.nextLine();

        try {
            if (op.equals("encrypt")) {
                encryptFile(filename, key);
            } else if (op.equals("decrypt")) {
                decryptFile(filename, key);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filename, String key) throws Exception {
        String filePath = BASE_DIR + filename;
        FileInputStream fis = new FileInputStream(filePath);
        FileOutputStream fos = new FileOutputStream(filePath + ".enc");
        
        byte[] buffer = new byte[1024];
        int read;
        while ((read = fis.read(buffer)) > 0) {
            for (int i = 0; i < read; i++) {
                buffer[i] ^= key.getBytes()[i % key.length()];
            }
            fos.write(buffer, 0, read);
        }
        
        fis.close();
        fos.close();
        new File(filePath).delete();
    }

    private static void decryptFile(String filename, String key) throws Exception {
        String filePath = BASE_DIR + filename.replace(".enc", "");
        FileInputStream fis = new FileInputStream(filename);
        FileOutputStream fos = new FileOutputStream(filePath);
        
        byte[] buffer = new byte[1024];
        int read;
        while ((read = fis.read(buffer)) > 0) {
            for (int i = 0; i < read; i++) {
                buffer[i] ^= key.getBytes()[i % key.length()];
            }
            fos.write(buffer, 0, read);
        }
        
        fis.close();
        fos.close();
    }
}