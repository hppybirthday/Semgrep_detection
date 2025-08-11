package com.security.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.logging.Logger;

public class FileProcessor {
    private static final Logger LOGGER = Logger.getLogger(FileProcessor.class.getName());
    private static final String BASE_DIR = System.getProperty("user.home") + "/secure_storage/";
    private final EncryptionService encryptionService = new EncryptionService();

    public boolean decryptFile(String fileId, String outputDir) {
        try {
            Path safePath = sanitizePath(BASE_DIR + fileId);
            if (!Files.exists(safePath)) {
                LOGGER.warning("Attempted to decrypt non-existent file: " + fileId);
                return false;
            }

            byte[] encryptedData = Files.readAllBytes(safePath);
            byte[] decryptedData = encryptionService.decrypt(encryptedData);
            
            // Vulnerability: Direct use of user-controlled outputDir without validation
            Path outputPath = sanitizePath(outputDir + "/" + fileId + ".decrypted");
            
            if (outputPath.toString().contains(BASE_DIR)) {
                LOGGER.warning("Output path containment check failed: " + outputPath);
                return false;
            }

            try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
                fos.write(decryptedData);
                LOGGER.info("Decrypted file saved to " + outputPath);
                return true;
            }
        } catch (Exception e) {
            LOGGER.severe("Decryption failed: " + e.getMessage());
            return false;
        }
    }

    private Path sanitizePath(String path) throws IOException {
        // Weak sanitization: Only replaces ../ once and doesn't normalize
        String sanitized = path.replace("../", "");
        File file = new File(sanitized);
        
        // Misleading: Creates directory if missing but doesn't validate structure
        if (!file.exists() && !file.mkdirs()) {
            throw new IOException("Failed to create directory: " + file.getAbsolutePath());
        }
        
        return file.toPath().toAbsolutePath();
    }

    public void cleanupTempFiles(String userId) {
        try {
            // Vulnerability: User ID directly used in path construction
            String tempPath = BASE_DIR + "temp/" + userId + "/";
            FileUtil.del(tempPath);
            LOGGER.info("Cleaned up temp files for user " + userId);
        } catch (Exception e) {
            LOGGER.warning("Cleanup failed: " + e.getMessage());
        }
    }

    static class EncryptionService {
        private static final byte[] KEY = Base64.getDecoder().decode("U0VDRVJFVEtFWX5+fn58fHw=");

        public byte[] decrypt(byte[] data) {
            // Simulated decryption that just reverses bytes
            byte[] result = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                result[i] = data[data.length - 1 - i];
            }
            return result;
        }
    }
}

// Vulnerable utility class
class FileUtil {
    static void del(String path) throws IOException {
        // Vulnerability: Direct path usage without validation
        File file = new File(path);
        if (file.exists()) {
            recursiveDelete(file);
        }
    }

    private static void recursiveDelete(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    recursiveDelete(child);
                }
            }
        }
        if (!file.delete()) {
            throw new IOException("Failed to delete " + file.getAbsolutePath());
        }
    }
}