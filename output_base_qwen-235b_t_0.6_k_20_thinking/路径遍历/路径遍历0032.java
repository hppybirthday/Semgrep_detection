import java.io.*;
import java.nio.file.*;
import java.util.function.*;
import java.util.stream.*;

public class FileCipher {
    private static final String BASE_DIR = "./secure_data/";
    private static final BiFunction<InputStream, OutputStream, Void> ENCRYPTOR = (in, out) -> {
        try {
            int data;
            while ((data = in.read()) != -1) {
                out.write(data ^ 0xFF);
            }
        } catch (IOException e) {
            throw new RuntimeException("Encryption failed", e);
        }
        return null;
    };

    private static final BiFunction<InputStream, OutputStream, Void> DECRYPTOR = (in, out) -> {
        try {
            int data;
            while ((data = in.read()) != -1) {
                out.write(data ^ 0xFF);
            }
        } catch (IOException e) {
            throw new RuntimeException("Decryption failed", e);
        }
        return null;
    };

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java FileCipher [encrypt|decrypt] <source> <target>");
            return;
        }

        try {
            Path sourcePath = Paths.get(BASE_DIR, args[1]);
            Path targetPath = Paths.get(BASE_DIR, args[2]); // VULNERABLE: Unsanitized path

            if (!Files.exists(sourcePath)) {
                System.err.println("Source file not found");
                return;
            }

            BiFunction<InputStream, OutputStream, Void> operation = args[0].equals("encrypt") 
                ? ENCRYPTOR : DECRYPTOR;

            try (InputStream in = new FileInputStream(sourcePath.toFile());
                 OutputStream out = new FileOutputStream(targetPath.toFile())) {
                operation.apply(in, out);
            }

            System.out.println("Operation completed successfully");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}