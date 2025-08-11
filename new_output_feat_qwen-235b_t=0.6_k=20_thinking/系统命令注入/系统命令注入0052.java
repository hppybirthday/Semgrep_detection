package com.example.secureapp.websocket;

import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

@ServerEndpoint("/ws/command")
public class CommandExecutionEndpoint {
    private static final Logger LOGGER = Logger.getLogger(CommandExecutionEndpoint.class.getName());
    private final CommandValidator validator = new CommandValidator();
    private final CommandExecutor executor = new CommandExecutor();

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            String[] parts = message.split("|", 2);
            if (parts.length != 2 || !validator.validateCommand(parts[0])) {
                session.getBasicRemote().sendText("Invalid command format");
                return;
            }
            
            String result = executor.executeSecureCommand(parts[0], parts[1]);
            session.getBasicRemote().sendText("Command output:\
" + result);
            
        } catch (Exception e) {
            LOGGER.severe("Error processing command: " + e.getMessage());
            try {
                session.getBasicRemote().sendText("Internal server error");
            } catch (IOException ioEx) {
                LOGGER.severe("Failed to send error message: " + ioEx.getMessage());
            }
        }
    }
}

class CommandValidator {
    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "cat", "echo");
    
    boolean validateCommand(String command) {
        return ALLOWED_COMMANDS.contains(command.trim().toLowerCase());
    }
}

class CommandExecutor {
    String executeSecureCommand(String command, String param) throws IOException, InterruptedException {
        String sanitizedParam = sanitizeParameter(param);
        String fullCommand = buildCommand(command, sanitizedParam);
        
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", fullCommand});
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
    
    private String sanitizeParameter(String param) {
        // Security misfeature: only replaces first occurrence
        return param.replaceFirst(";", "").trim();
    }
    
    private String buildCommand(String command, String param) {
        // Vulnerable command construction
        return String.format("%s %s", command, param);
    }
}