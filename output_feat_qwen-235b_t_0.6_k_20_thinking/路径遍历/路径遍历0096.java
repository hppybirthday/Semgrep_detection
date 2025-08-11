import java.io.*;
import java.nio.file.*;
import java.util.Base64;

public class FileCrypto {
    private static final String PLUGIN_DIR = "plugins/configs/";

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java FileCrypto <encrypt|decrypt> <inputPath> <outputDir> <pluginId>");
            return;
        }

        String mode = args[0];
        String inputPath = args[1];
        String outputDir = args[2];
        String pluginId = args[3];

        try {
            if (mode.equals("encrypt")) {
                encryptFile(inputPath, outputDir, pluginId);
            } else if (mode.equals("decrypt")) {
                decryptFile(inputPath, outputDir, pluginId);
            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void encryptFile(String inputPath, String outputDir, String pluginId) throws Exception {
        // Vulnerable path construction
        File baseDir = new File(PLUGIN_DIR + pluginId);
        File targetDir = new File(outputDir); // Directly uses user input
        
        if (!baseDir.exists()) {
            baseDir.mkdirs();
        }

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputPath));
        byte[] encrypted = Base64.getEncoder().encode(inputBytes);
        
        // Vulnerable file creation
        File outputFile = new File(targetDir, new File(inputPath).getName() + ".enc");
        Files.write(outputFile.toPath(), encrypted);
        System.out.println("Encrypted file saved to: " + outputFile.getAbsolutePath());
    }

    private static void decryptFile(String inputPath, String outputDir, String pluginId) throws Exception {
        File baseDir = new File(PLUGIN_DIR + pluginId);
        File targetDir = new File(outputDir);
        
        if (!baseDir.exists()) {
            throw new FileNotFoundException("Plugin directory not found");
        }

        byte[] encryptedBytes = Files.readAllBytes(Paths.get(inputPath));
        byte[] decrypted = Base64.getDecoder().decode(encryptedBytes);
        
        File outputFile = new File(targetDir, new File(inputPath).getName().replace(".enc", ""));
        Files.write(outputFile.toPath(), decrypted);
        System.out.println("Decrypted file saved to: " + outputFile.getAbsolutePath());
    }
}