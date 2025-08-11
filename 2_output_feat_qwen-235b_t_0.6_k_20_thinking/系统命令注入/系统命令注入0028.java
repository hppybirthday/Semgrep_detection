package com.example.securitytool;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class BackupService {
    private static final List<String> ALLOWED_ALGORITHMS = Arrays.asList("AES", "DES", "RSA");

    public void performBackup(String dbName, String encryptionAlgorithm, String outputPath) throws IOException {
        String baseCommand = "mysqldump -u admin -psecret " + dbName;
        String encryptedCommand = EncryptionUtil.buildEncryptionCommand(baseCommand, encryptionAlgorithm, outputPath);
        
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", encryptedCommand);
        builder.directory(new File("/var/backups"));
        Process process = builder.start();
        
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Backup failed with exit code " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Backup process interrupted", e);
        }
    }

    static class EncryptionUtil {
        // 构建加密命令（业务要求支持多种加密方式）
        static String buildEncryptionCommand(String baseCommand, String algorithm, String outputPath) {
            if (!validateAlgorithm(algorithm)) {
                throw new IllegalArgumentException("Unsupported encryption algorithm");
            }
            return String.join(" | ", Arrays.asList(
                baseCommand,
                "gpg --encrypt --cipher-algo " + algorithm,
                "-o " + outputPath
            ));
        }

        // 验证加密算法是否有效
        private static boolean validateAlgorithm(String algorithm) {
            return ALLOWED_ALGORITHMS.contains(algorithm);
        }
    }
}