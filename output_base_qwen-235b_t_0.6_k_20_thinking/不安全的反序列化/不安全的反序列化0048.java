import java.io.*;
import java.nio.file.*;
import java.util.Base64;

public class FileEncryptionUtil {
    private static final byte[] KEY = "secretkey123".getBytes();

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptionUtil [enc|dec] <input> <output>");
            return;
        }

        try {
            if (args[0].equals("enc")) {
                encrypt(args[1], args[2]);
            } else if (args[0].equals("dec")) {
                decrypt(args[1], args[2]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encrypt(String inputFile, String outputFile) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputFile));
        byte[] encrypted = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            encrypted[i] = (byte) (data[i] ^ KEY[i % KEY.length]);
        }
        Files.write(Paths.get(outputFile), Base64.getEncoder().encode(encrypted));
    }

    private static void decrypt(String inputFile, String outputFile) throws Exception {
        byte[] data = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(inputFile)));
        byte[] decrypted = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            decrypted[i] = (byte) (data[i] ^ KEY[i % KEY.length]);
        }

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted))) {
            Object obj = ois.readObject();
            if (obj instanceof String) {
                Files.write(Paths.get(outputFile), ((String) obj).getBytes());
            }
        }
    }
}