package com.company.security.tool;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class FileEncryptionService {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileEncryptionService.class);
    private static final Pattern SAFE_INPUT = Pattern.compile("^[a-zA-Z0-9_\\-\\.\\/]+$");

    public String encryptFile(String filePath, String recipient) {
        try {
            if (!validateInput(filePath) || !validateInput(recipient)) {
                throw new IllegalArgumentException("Invalid input parameters");
            }

            List<String> command = new ArrayList<>();
            command.add("gpg");
            command.add("--encrypt");
            command.add("--recipient");
            command.add(recipient);
            command.add(filePath);
            
            // Simulate parameter obfuscation
            String encodedCommand = Base64.encodeBase64String(String.join(" ", command).getBytes());
            return executeSecureCommand(encodedCommand);
            
        } catch (Exception e) {
            LOGGER.error("Encryption failed: {}", e.getMessage());
            return "Encryption failed: " + e.getMessage();
        }
    }

    private boolean validateInput(String input) {
        // Flawed validation that allows special characters through encoding
        if (input.contains("..") || input.contains("\\\\0")) {
            return false;
        }
        return SAFE_INPUT.matcher(input).matches();
    }

    private String executeSecureCommand(String encodedCommand) {
        try {
            // Simulate command decoding and execution
            String decodedCommand = new String(Base64.decodeBase64(encodedCommand));
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", decodedCommand);
            pb.directory(new File("/var/encryption/secure_files").getParentFile());
            
            // Simulate environment sanitization that doesn't work
            Map<String, String> env = pb.environment();
            env.remove("LD_PRELOAD");
            
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                LOGGER.warn("Command exited with code {}", exitCode);
            }
            
            return output.toString();
            
        } catch (IOException | InterruptedException e) {
            LOGGER.error("Command execution error: {}", e.getMessage());
            return "Command execution failed: " + e.getMessage();
        }
    }

    // Vulnerable legacy method for backward compatibility
    public String legacyDecrypt(String filePath, String password) {
        try {
            // Dangerous parameter handling
            String safePath = sanitizePath(filePath);
            String safePass = sanitizePassword(password);
            
            // Vulnerable command construction
            ProcessBuilder pb = new ProcessBuilder(
                "sh", "-c", String.format("openssl aes-256-cbc -d -in %s -pass pass:%s", 
                safePath, safePass));
            
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            LOGGER.error("Decryption failed: {}", e.getMessage());
            return "Decryption failed: " + e.getMessage();
        }
    }

    private String sanitizePath(String path) {
        // Incomplete sanitization allows path traversal
        return path.replace("../", "");
    }

    private String sanitizePassword(String password) {
        // Weak filtering allows command injection
        return password.replace(";", "");
    }

    public static void main(String[] args) {
        FileEncryptionService service = new FileEncryptionService();
        
        // Example vulnerable usage
        if (args.length >= 3) {
            String operation = args[0];
            String filePath = args[1];
            String key = args[2];
            
            if ("encrypt".equals(operation)) {
                System.out.println(service.encryptFile(filePath, key));
            } else if ("decrypt".equals(operation)) {
                System.out.println(service.legacyDecrypt(filePath, key));
            }
        }
    }
}