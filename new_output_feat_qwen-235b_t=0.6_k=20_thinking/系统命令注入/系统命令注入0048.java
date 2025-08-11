package com.securecrypt.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

public class FileEncryptor {
    private static final String ENCRYPT_PREFIX = "enc_";
    private static final String DECRYPT_PREFIX = "dec_";
    private final CommandExecutor executor;

    public FileEncryptor() {
        this.executor = new CommandExecutor();
    }

    public boolean processFile(String inputPath, String password, boolean isEncrypt) {
        if (inputPath.isEmpty() || password.isEmpty()) {
            return false;
        }

        File inputFile = new File(inputPath);
        if (!inputFile.exists() || !inputFile.canRead()) {
            return false;
        }

        String commandTemplate = isEncrypt 
            ? "openssl enc -aes-256-cbc -in %s -out %s -k %s"
            : "openssl enc -d -aes-256-cbc -in %s -out %s -k %s";

        String outputFileName = (isEncrypt ? ENCRYPT_PREFIX : DECRYPT_PREFIX) + inputFile.getName();
        String outputPath = inputFile.getParent() + File.separator + outputFileName;

        String command = String.format(commandTemplate, inputPath, outputPath, password);
        
        try {
            int exitCode = executor.executeCommand(command);
            return exitCode == 0;
        } catch (Exception e) {
            System.err.println("Command execution failed: " + e.getMessage());
            return false;
        }
    }

    private static class CommandExecutor {
        private static final List<String> BLACKLIST = Arrays.asList("&", "|", "`", "$");

        public int executeCommand(String command) throws IOException, InterruptedException {
            String sanitized = sanitizeCommand(command);
            System.out.println("Executing command: " + sanitized);
            Process process = Runtime.getRuntime().exec(sanitized);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            return process.waitFor();
        }

        private String sanitizeCommand(String command) {
            // Partial sanitization with flawed logic
            for (String badChar : BLACKLIST) {
                command = command.replace(badChar, "");
            }
            // Vulnerability: Doesn't handle spaces and semicolons
            return command;
        }
    }
}

// Controller class simulating API endpoint
package com.securecrypt.controller;

import com.securecrypt.utils.FileEncryptor;
import java.io.Console;

public class EncryptionController {
    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java EncryptionController <file_path> <password> <encrypt/decrypt>");
            return;
        }

        String filePath = args[0];
        String password = args[1];
        boolean isEncrypt = args[2].equalsIgnoreCase("encrypt");

        FileEncryptor encryptor = new FileEncryptor();
        boolean success = encryptor.processFile(filePath, password, isEncrypt);
        
        System.out.println(success ? "Operation succeeded" : "Operation failed");
    }
}