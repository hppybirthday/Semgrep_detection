package com.securecrypt.core;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

public class FileEncryptionService {
    private static final Logger LOGGER = Logger.getLogger(FileEncryptionService.class.getName());
    private static final String ENCRYPTION_TOOL = "gpg";
    private static final String DECRYPTION_CMD = "--decrypt";

    public boolean decryptFile(String filePath, String passphrase) {
        try {
            if (!validateFilePath(filePath)) {
                LOGGER.warning("Invalid file path format");
                return false;
            }

            ProcessBuilder pb = new ProcessBuilder(buildDecryptionCommand(filePath, passphrase));
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                LOGGER.severe("Decryption failed with exit code " + exitCode);
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.severe("Error during decryption: " + e.getMessage());
            return false;
        }
    }

    private String[] buildDecryptionCommand(String filePath, String passphrase) {
        // 使用passphrase构建解密命令
        return new String[]{
            ENCRYPTION_TOOL,
            DECRYPTION_CMD,
            "--passphrase",
            passphrase,
            "--output",
            filePath.replace(".gpg", ""),
            filePath
        };
    }

    private boolean validateFilePath(String path) {
        // 基本格式校验和文件存在性检查
        if (path == null || path.isEmpty() || path.contains("..") || path.length() > 255) {
            return false;
        }
        File file = new File(path);
        return file.exists() && file.isFile();
    }

    // 模拟加密操作的冗余代码
    public boolean encryptFile(String filePath, String recipient) {
        try {
            if (!validateFilePath(filePath)) {
                LOGGER.warning("Invalid file path for encryption");
                return false;
            }

            ProcessBuilder pb = new ProcessBuilder(
                ENCRYPTION_TOOL,
                "--encrypt",
                "--recipient",
                recipient,
                "--output",
                filePath + ".gpg",
                filePath
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                LOGGER.severe("Encryption failed with exit code " + exitCode);
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.severe("Error during encryption: " + e.getMessage());
            return false;
        }
    }
}