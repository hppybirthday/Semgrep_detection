import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class FileEncryptorDecryptor {
    private static final String BASE_DIR = "/var/secure_files/";
    private static final byte ENCRYPTION_KEY = (byte) 0xA5;

    public static void main(String[] args) {
        try {
            System.out.println("Enter file path (relative to " + BASE_DIR + "):");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String userInput = reader.readLine();
            
            // Vulnerable path construction
            Path targetPath = Paths.get(BASE_DIR, userInput).normalize();
            
            System.out.println("Choose operation: 1-Encrypt 2-Decrypt");
            int choice = Integer.parseInt(reader.readLine());
            
            switch (choice) {
                case 1 -> processFile(targetPath, FileEncryptorDecryptor::encrypt);
                case 2 -> processFile(targetPath, FileEncryptorDecryptor::decrypt);
                default -> System.out.println("Invalid choice");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static void processFile(Path filePath, Function<byte[], byte[]> processor) throws IOException {
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found: " + filePath);
        }

        try (InputStream is = Files.newInputStream(filePath);
             ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            byte[] data = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(data)) != -1) {
                buffer.write(data, 0, bytesRead);
            }
            
            byte[] processedData = processor.apply(buffer.toByteArray());
            
            // Save processed file with .enc extension
            Path outputPath = filePath.getParent().resolve(filePath.getFileName() + ".processed");
            
            try (OutputStream os = Files.newOutputStream(outputPath, StandardOpenOption.CREATE)) {
                os.write(processedData);
                System.out.println("Operation completed. Output saved to: " + outputPath);
            }
        }
    }

    private static byte[] encrypt(byte[] data) {
        return Arrays.stream(data)
                   .map(b -> b ^ ENCRYPTION_KEY)
                   .collect(() -> new ByteArrayOutputStream(),
                            (out, b) -> out.write(b),
                            (out1, out2) -> out1.write(out2.toByteArray(), 0, out2.size()))
                   .toByteArray();
    }

    private static byte[] decrypt(byte[] data) {
        return encrypt(data); // Symmetric operation
    }
}