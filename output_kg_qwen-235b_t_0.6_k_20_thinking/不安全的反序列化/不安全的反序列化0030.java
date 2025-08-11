import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.function.Function;

public class FileCryptor {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY = "1234567890123456";

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java FileCryptor <encrypt|decrypt> <filepath>");
            return;
        }

        String operation = args[0];
        String filePath = args[1];

        try {
            if (operation.equals("encrypt")) {
                encryptFile(filePath);
            } else if (operation.equals("decrypt")) {
                decryptFile(filePath, obj -> {
                    System.out.println("Decrypted object: " + obj);
                    return null;
                });
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());

        Object obj = new EncryptedData("Secret Content"); // Example serializable object
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();

        byte[] encryptedData = cipher.doFinal(bos.toByteArray());
        Path outputPath = Paths.get(filePath + ".encrypted");
        Files.write(outputPath, encryptedData);
        System.out.println("File encrypted to: " + outputPath);
    }

    private static void decryptFile(String filePath, Function<Object, Void> handler) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey());

        Path path = Paths.get(filePath);
        byte[] encryptedData = Files.readAllBytes(path);
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // Vulnerable deserialization point
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedData));
        Object obj = ois.readObject(); // UNSAFE DESERIALIZATION
        ois.close();

        handler.apply(obj);
    }

    private static SecretKey getSecretKey() {
        return new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
    }
}

// Example serializable class
class EncryptedData implements Serializable {
    private String content;

    public EncryptedData(String content) {
        this.content = content;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        // Simulate dangerous operation
        if (content.contains("malicious")) {
            Runtime.getRuntime().exec("calc"); // Simulated RCE
        }
    }
}