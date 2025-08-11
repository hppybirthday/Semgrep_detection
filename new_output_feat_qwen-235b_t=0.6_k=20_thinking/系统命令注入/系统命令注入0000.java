package com.securecrypt.tool;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/encrypt")
public class FileEncryptionEndpoint {
    
    private static final Logger LOGGER = Logger.getLogger(FileEncryptionEndpoint.class.getName());
    private static final String BASE_DIR = "/var/secure_storage/";
    
    @OnMessage
    public void onMessage(String filePath, Session session) {
        try {
            FileValidator validator = new FileValidator(BASE_DIR);
            if(!validator.validateFilePath(filePath)) {
                session.getBasicRemote().sendText("Invalid file path");
                return;
            }
            
            FileEncryptor encryptor = new FileEncryptor();
            String result = encryptor.encryptFile(filePath);
            session.getBasicRemote().sendText(result);
            
        } catch (Exception e) {
            LOGGER.severe("Encryption error: " + e.getMessage());
            try {
                session.getBasicRemote().sendText("Internal server error");
            } catch (IOException ioEx) {
                // Ignore
            }
        }
    }
}

class FileValidator {
    private final String allowedBasePath;
    
    public FileValidator(String basePath) {
        this.allowedBasePath = basePath;
    }
    
    public boolean validateFilePath(String inputPath) {
        // Basic path validation to prevent directory traversal
        if(inputPath.contains("..") || inputPath.startsWith("/")) {
            return false;
        }
        
        try {
            Path resolvedPath = Paths.get(allowedBasePath, inputPath).toRealPath();
            return resolvedPath.startsWith(allowedBasePath);
        } catch (IOException e) {
            return false;
        }
    }
}

class FileEncryptor {
    private static final List<String> ENCRYPTION_KEYS = Arrays.asList("AES-256", "RSA-2048");
    
    public String encryptFile(String filePath) throws IOException, InterruptedException {
        String encryptionKey = getOptimalEncryptionKey();
        
        // Build encryption command with user input
        String command = String.format("openssl enc -aes-256-cbc -in %s -out %s.enc -pass pass:%s",
            filePath, filePath, encryptionKey);
            
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if(exitCode != 0) {
            throw new IOException("Encryption failed with code " + exitCode);
        }
        
        return "Encrypted successfully: " + output.toString();
    }
    
    private String getOptimalEncryptionKey() {
        // Simulate key selection logic
        return ENCRYPTION_KEYS.get((int)(Math.random() * ENCRYPTION_KEYS.size()));
    }
}