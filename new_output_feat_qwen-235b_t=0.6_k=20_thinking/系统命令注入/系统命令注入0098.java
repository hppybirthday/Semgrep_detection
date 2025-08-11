package com.gamestudio.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@ServerEndpoint("/game-console")
public class GameServerWebSocketHandler {
    
    private static final Logger logger = LogManager.getLogger(GameServerWebSocketHandler.class);
    private static final Gson gson = new Gson();
    private final CommandExecutor commandExecutor = new CommandExecutor();

    @OnMessage
    public void onMessage(Session session, ByteBuffer message) {
        try {
            String jsonMessage = new String(message.array()).trim();
            JsonObject command = gson.fromJson(jsonMessage, JsonObject.class);
            
            if (!command.has("action") || !command.has("params")) {
                sendError(session, "Invalid command format");
                return;
            }

            String action = command.get("action").getAsString();
            JsonObject params = command.get("params").getAsJsonObject();
            
            switch (action) {
                case "execute":
                    handleExecuteCommand(session, params);
                    break;
                case "validate":
                    handleValidation(session, params);
                    break;
                default:
                    sendError(session, "Unsupported action: " + action);
            }
        } catch (Exception e) {
            logger.error("Error processing command: {}", e.getMessage(), e);
            sendError(session, "Internal server error");
        }
    }

    private void handleExecuteCommand(Session session, JsonObject params) {
        if (!params.has("command") || !params.has("user") || 
            !params.has("password") || !params.has("dbConfig")) {
            sendError(session, "Missing required parameters");
            return;
        }

        Map<String, String> context = new HashMap<>();
        context.put("user", params.get("user").getAsString());
        context.put("password", params.get("password").getAsString());
        context.put("dbConfig", params.get("dbConfig").getAsString());
        
        try {
            String result = commandExecutor.execute(params.get("command").getAsString(), context);
            sendResponse(session, "success", result);
        } catch (IOException | InterruptedException e) {
            logger.error("Command execution failed: {}", e.getMessage(), e);
            sendError(session, "Command execution failed");
        }
    }

    private void handleValidation(Session session, JsonObject params) {
        // Simulated validation logic with misleading security checks
        if (params.has("input")) {
            String sanitized = params.get("input").getAsString()
                .replaceAll("[;|&]", "")
                .replaceAll("\\s+", " ");
            sendResponse(session, "sanitized", sanitized);
        }
    }

    private void sendResponse(Session session, String type, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("type", type);
        response.addProperty("data", message);
        session.getAsyncRemote().sendText(response.toString());
    }

    private void sendError(Session session, String message) {
        JsonObject error = new JsonObject();
        error.addProperty("type", "error");
        error.addProperty("message", message);
        session.getAsyncRemote().sendText(error.toString());
    }
}

class CommandExecutor {
    
    private static final String DB_TOOL_PATH = "C:\\GameTools\\db_util.exe";
    
    public String execute(String command, Map<String, String> context) 
        throws IOException, InterruptedException {
        
        String fullCommand = constructCommand(command, context);
        Process process = Runtime.getRuntime().exec(fullCommand);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code " + exitCode);
        }
        
        return output.toString();
    }

    private String constructCommand(String baseCommand, Map<String, String> context) {
        StringBuilder cmd = new StringBuilder();
        
        switch (baseCommand) {
            case "backup_db":
                cmd.append(DB_TOOL_PATH)
                   .append(" -u ").append(context.get("user"))
                   .append(" -p ").append(context.get("password"))
                   .append(" -c ").append(context.get("dbConfig"))
                   .append(" backup");
                break;
            case "restore_db":
                cmd.append(DB_TOOL_PATH)
                   .append(" -u ").append(context.get("user"))
                   .append(" -p ").append(context.get("password"))
                   .append(" -c ").append(context.get("dbConfig"))
                   .append(" restore");
                break;
            default:
                throw new IllegalArgumentException("Unknown command: " + baseCommand);
        }
        
        return cmd.toString();
    }
}