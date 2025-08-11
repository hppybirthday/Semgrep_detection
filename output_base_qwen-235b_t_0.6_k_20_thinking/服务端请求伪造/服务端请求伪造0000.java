import java.io.*;
import java.net.*;
import java.util.Base64;

public class FileEncryptor {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java FileEncryptor <encrypt/decrypt> <inputPath> <outputPath>");
            return;
        }

        String operation = args[0];
        String inputPath = args[1];
        String outputPath = args[2];

        try {
            if (operation.equals("encrypt")) {
                encryptFile(inputPath, outputPath);
            } else if (operation.equals("decrypt")) {
                decryptFile(inputPath, outputPath);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptFile(String inputPath, String outputPath) throws IOException {
        try (InputStream is = getInputSteam(inputPath);
             OutputStream os = new FileOutputStream(outputPath)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                byte[] encrypted = Base64.getEncoder().encode(buffer, 0, bytesRead);
                os.write(encrypted);
            }
        }
    }

    private static void decryptFile(String inputPath, String outputPath) throws IOException {
        try (InputStream is = getInputSteam(inputPath);
             OutputStream os = new FileOutputStream(outputPath)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                byte[] decrypted = Base64.getDecoder().decode(buffer, 0, bytesRead);
                os.write(decrypted);
            }
        }
    }

    private static InputStream getInputSteam(String path) throws IOException {
        if (path.startsWith("http")) {
            try {
                // Vulnerable point: Directly using user input to create URL
                URL url = new URL(path);
                return url.openStream();
            } catch (MalformedURLException e) {
                throw new IOException("Invalid URL: " + path);
            }
        } else {
            return new FileInputStream(path);
        }
    }
}