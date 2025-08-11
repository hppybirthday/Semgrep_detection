package com.iot.device.controller;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@ServerEndpoint("/ws/device")
public class DeviceControlEndpoint {
    private static final Map<String, Session> DEVICE_SESSIONS = new ConcurrentHashMap<>();
    private static final Pattern SAFE_CHAR_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\\\-]+$");

    @OnOpen
    public void onOpen(Session session) {
        DEVICE_SESSIONS.put(session.getId(), session);
    }

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            JsonMessage jsonMsg = JsonParser.parse(message);
            if ("EXECUTE_CMD".equals(jsonMsg.getType())) {
                String deviceId = jsonMsg.getDeviceId();
                String cmd = jsonMsg.getCommand();
                String param = jsonMsg.getParam();
                
                if (!validateInput(deviceId) || !validateInput(param)) {
                    sendError(session, "Invalid input format");
                    return;
                }
                
                DeviceCommandExecutor executor = new DeviceCommandExecutor();
                String result = executor.executeCommand(deviceId, cmd, param);
                sendResponse(session, result);
            }
        } catch (Exception e) {
            sendError(session, "Internal error: " + e.getMessage());
        }
    }

    private boolean validateInput(String input) {
        return input != null && SAFE_CHAR_PATTERN.matcher(input).matches();
    }

    @OnClose
    public void onClose(Session session) {
        DEVICE_SESSIONS.remove(session.getId());
    }

    private void sendResponse(Session session, String message) {
        try {
            session.getBasicRemote().sendText(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sendError(Session session, String errorMessage) {
        sendResponse(session, "{\\"error\\":\\"" + errorMessage + "\\"}");
    }

    static class JsonParser {
        static JsonMessage parse(String json) {
            // 简化版JSON解析（实际使用Jackson等库）
            JsonMessage msg = new JsonMessage();
            String[] pairs = json.split(",");
            for (String pair : pairs) {
                String[] entry = pair.split(":");
                if (entry.length == 2) {
                    String key = entry[0].trim().replaceAll("[{}\\"]", "");
                    String value = entry[1].trim().replaceAll("[{}\\"]", "");
                    switch (key) {
                        case "type": msg.setType(value); break;
                        case "deviceId": msg.setDeviceId(value); break;
                        case "command": msg.setCommand(value); break;
                        case "param": msg.setParam(value); break;
                    }
                }
            }
            return msg;
        }
    }

    static class JsonMessage {
        private String type;
        private String deviceId;
        private String command;
        private String param;
        // getters/setters
    }
}

class DeviceCommandExecutor {
    String executeCommand(String deviceId, String cmd, String param) {
        try {
            String fullCommand = buildCommand(deviceId, cmd, param);
            Process process = Runtime.getRuntime().exec(fullCommand);
            // 省略流处理代码
            return "Command executed successfully";
        } catch (Exception e) {
            return "Execution failed: " + e.getMessage();
        }
    }

    private String buildCommand(String deviceId, String cmd, String param) {
        // 命令构造逻辑
        return String.format("/opt/iot/bin/%s_ctl -d %s -p %s", cmd, deviceId, param);
    }
}