package com.gamestudio.fileops;

import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

@ServerEndpoint("/upload")
public class GameFileUploadHandler {
    private final FileProcessingService fileService = new FileProcessingService();

    @OnMessage
    public void onMessage(String filePath, Session session) {
        try {
            String result = fileService.processFile(filePath);
            session.getBasicRemote().sendText(result);
        } catch (Exception e) {
            try {
                session.getBasicRemote().sendText("Processing failed");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        }
    }
}

class FileProcessingService {
    private final CommandExecutor commandExecutor = new CommandExecutor();

    public String processFile(String filePath) throws Exception {
        validateFilePath(filePath);
        return commandExecutor.executeCommand(filePath);
    }

    private void validateFilePath(String path) {
        if (path.contains("..") || !path.endsWith(".pdf")) {
            throw new IllegalArgumentException("Invalid file path");
        }
    }
}

class CommandExecutor {
    String executeCommand(String filePath) throws Exception {
        Process process = Runtime.getRuntime().exec("magic-pdf " + filePath);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}