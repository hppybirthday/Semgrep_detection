import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptDecrypt {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptDecrypt <encrypt|decrypt> <fileUrl> <key>");
            return;
        }

        String mode = args[0];
        String fileUrl = args[1];
        String key = args[2];

        try {
            String fileContent = downloadFile(fileUrl);
            
            if (mode.equals("encrypt")) {
                String encrypted = encrypt(fileContent, key);
                System.out.println("Encrypted content: " + encrypted);
            } else if (mode.equals("decrypt")) {
                String decrypted = decrypt(fileContent, key);
                System.out.println("Decrypted content: " + decrypted);
            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static String downloadFile(String fileUrl) throws IOException {
        URL url = new URL(fileUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() != 200) {
            throw new IOException("Failed to download file: HTTP " + connection.getResponseCode());
        }
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder content = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\
");
        }
        
        reader.close();
        return content.toString();
    }

    private static String encrypt(String data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedData, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }
}