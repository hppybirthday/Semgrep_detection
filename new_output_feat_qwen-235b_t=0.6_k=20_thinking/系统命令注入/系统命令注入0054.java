package com.iot.device.controller;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;

public class DeviceControlServer extends WebSocketServer {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final DeviceCommandExecutor commandExecutor = new DeviceCommandExecutor();

    public DeviceControlServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        conn.send("{\\"status\\":\\"connected\\"}");
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            JsonNode request = objectMapper.readTree(message);
            String commandType = request.get("type").asText();
            JsonNode paramsNode = request.get("params");
            
            List<String> params = new ArrayList<>();
            if (paramsNode.isArray()) {
                paramsNode.forEach(element -> params.add(element.asText()));
            }
            
            String result = commandExecutor.executeCommand(commandType, params.toArray(new String[0]));
            conn.send("{\\"result\\":\\"" + result + "\\"}");
            
        } catch (Exception e) {
            conn.send("{\\"error\\":\\"Invalid request format\\"}");
        }
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {}

    @Override
    public void onError(WebSocket conn, Exception ex) {}

    public static void main(String[] args) {
        DeviceControlServer server = new DeviceControlServer(8081);
        server.start();
    }
}

class DeviceCommandExecutor {
    private final SecurityValidator securityValidator = new SecurityValidator();

    public String executeCommand(String commandType, String[] params) throws IOException {
        if (!securityValidator.validateCommand(commandType)) {
            return "Command not allowed";
        }

        try {
            CommandLine commandLine = new CommandLine("/usr/bin/device_ctl");
            commandLine.addArgument(commandType);
            
            // Vulnerable point: Directly adding user-controlled parameters
            for (String param : params) {
                commandLine.addArgument(param);
            }

            DefaultExecutor executor = new DefaultExecutor();
            return executor.executeToString(commandLine);
            
        } catch (ExecuteException e) {
            return "Execution failed: " + e.getMessage();
        }
    }
}

class SecurityValidator {
    // Whitelist validation for command types
    public boolean validateCommand(String commandType) {
        return commandType.matches("^(reboot|update|status|log)$");
    }

    // Misleading security function that doesn't properly sanitize parameters
    @Deprecated
    public String sanitizeParameter(String param) {
        return param.replaceAll("[;|&]", "");  // Incomplete sanitization
    }
}