package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/device")
public class DeviceControlController {
    
    private final List<WebSocketHttpSession> sessions = new CopyOnWriteArrayList<>();

    @GetMapping("/connect")
    public void connectWebSocket(WebSocketHttpSession session) {
        session.setWebSocketHandler(new TextWebSocketHandler() {
            @Override
            public void handleTextMessage(WebSocketHttpSession session, TextMessage message) {
                try {
                    String[] parts = message.getPayload().split(" ");
                    String command = parts[0];
                    String[] args = new String[parts.length - 1];
                    System.arraycopy(parts, 1, args, 0, args.length);
                    
                    List<String> cmdList = new ArrayList<>();
                    cmdList.add("/bin/bash");
                    cmdList.add("-c");
                    cmdList.add("/usr/local/bin/device_ctl " + command);
                    
                    // 漏洞点：直接拼接用户输入参数到命令数组
                    for (String arg : args) {
                        cmdList.add(arg);
                    }
                    
                    ProcessBuilder pb = new ProcessBuilder(cmdList);
                    Process process = pb.start();
                    
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    session.sendMessage(new TextMessage("RESPONSE: " + output.toString()));
                    
                } catch (Exception e) {
                    try {
                        session.sendMessage(new TextMessage("ERROR: " + e.getMessage()));
                    } catch (IOException ioException) {
                        ioException.printStackTrace();
                    }
                }
            }
        });
        
        try {
            session.afterConnectionEstablished();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}