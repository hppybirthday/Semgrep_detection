package com.example.securecrypt;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/ws/crypto")
public class CryptoWebSocket {
    private static final String ENCRYPTION_TOOL = "magic-pdf";
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(".pdf", ".docx", ".xlsx");

    @OnMessage
    public void onMessage(String command, Session session) {
        try {
            String processedCmd = processCommand(command);
            if (isValidCommand(processedCmd)) {
                String result = executeCommand(processedCmd);
                session.getBasicRemote().sendText("Result: " + result);
            } else {
                session.getBasicRemote().sendText("Invalid command format");
            }
        } catch (Exception e) {
            session.onError(e);
        }
    }

    private String processCommand(String input) {
        String[] parts = input.split(" ", 2);
        if (parts.length < 2 || !parts[0].equals(ENCRYPTION_TOOL)) {
            return "";
        }
        return parts[1];
    }

    private boolean isValidCommand(String cmd) {
        if (cmd.contains("..") || cmd.contains("~")) {
            return false;
        }
        
        // Check file extension (business requirement)
        String lowerCmd = cmd.toLowerCase();
        return ALLOWED_EXTENSIONS.stream().anyMatch(lowerCmd::endsWith);
    }

    private String executeCommand(String cmd) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(
            ENCRYPTION_TOOL + " " + cmd);
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }
}