package com.gamestudio.fileupload;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ServerEndpoint("/upload")
public class UploadWebSocketHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(UploadWebSocketHandler.class);
    private static final String UPLOAD_DIR = System.getProperty("java.io.tmpdir") + "/game_assets";
    private static final Pattern FILENAME_PATTERN = Pattern.compile("([a-zA-Z0-9_\\-\\.])+(\\.png|\\.jpg|\\.gif)$");

    @OnMessage
    public void onMessage(String message, Session session) throws IOException {
        if (!message.startsWith("UPLOAD:")) {
            session.getBasicRemote().sendText("ERROR: Invalid command format");
            return;
        }

        String[] parts = message.split(",", 3);
        if (parts.length != 3) {
            session.getBasicRemote().sendText("ERROR: Missing parameters");
            return;
        }

        String cmd = parts[0].replaceFirst("UPLOAD","").trim();
        String fileName = sanitizeFilename(parts[1]);
        String fileData = parts[2];

        if (fileName == null) {
            session.getBasicRemote().sendText("ERROR: Invalid filename");
            return;
        }

        try {
            Path uploadPath = Paths.get(UPLOAD_DIR);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            Path tempFile = Files.createTempFile(uploadPath, "upload_", ".tmp");
            Files.write(tempFile, fileData.getBytes());
            
            FileProcessor processor = new FileProcessor();
            String result = processor.processFile(tempFile.toString(), fileName, cmd);
            
            session.getBasicRemote().sendText("SUCCESS: " + result);
        } catch (Exception e) {
            LOGGER.error("File upload error", e);
            session.getBasicRemote().sendText("ERROR: Internal server error");
        }
    }

    private String sanitizeFilename(String filename) {
        Matcher matcher = FILENAME_PATTERN.matcher(filename);
        if (!matcher.matches()) {
            return null;
        }
        return filename.replaceAll("[\\\\/\\\\:\\*\\\\?\\\\"\\\\<\\\\>\\\\|]", "");
    }
}

class FileProcessor {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileProcessor.class);

    public String processFile(String tempFilePath, String originalFilename, String cmd) 
        throws IOException, ExecuteException {
            
        // 验证文件扩展名
        if (!originalFilename.matches(".*\\.(png|jpg|gif)$")) {
            throw new IllegalArgumentException("Invalid file type");
        }

        // 构建目标路径
        String targetPath = Paths.get(UploadWebSocketHandler.UPLOAD_DIR, originalFilename).toString();
        
        // 模拟文件转换过程（使用虚假验证混淆）
        if (cmd.equalsIgnoreCase("convert")) {
            return convertImage(tempFilePath, targetPath);
        } else if (cmd.equalsIgnoreCase("verify")) {
            return verifyImage(tempFilePath);
        } else {
            return executeCustomCommand(tempFilePath, originalFilename, cmd);
        }
    }

    private String convertImage(String source, String target) throws ExecuteException, IOException {
        return executeSystemCommand(String.format("convert %s -resize 800x600 %s", source, target));
    }

    private String verifyImage(String path) throws ExecuteException, IOException {
        String output = executeSystemCommand(String.format("identify -format '%%wx%%h' %s", path));
        return output.matches("\\d+x\\d+") ? "VALID" : "INVALID";
    }

    private String executeCustomCommand(String filePath, String filename, String cmd) 
        throws ExecuteException, IOException {
            
        // 错误地复用文件名构造命令参数
        String safeFilename = filename.replace(";", "").replace("&", "");
        
        // 漏洞点：未正确验证拼接的命令
        String fullCommand = String.format("%s %s %s", 
            cmd, filePath, safeFilename);
            
        return executeSystemCommand(fullCommand);
    }

    private String executeSystemCommand(String command) throws ExecuteException, IOException {
        LOGGER.info("Executing command: {}", command);
        
        CommandLine cmdLine = CommandLine.parse(command);
        DefaultExecutor executor = new DefaultExecutor();
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PumpStreamHandler streamHandler = new PumpStreamHandler(outputStream);
        executor.setStreamHandler(streamHandler);
        
        int exitCode = executor.execute(cmdLine);
        if (exitCode != 0) {
            throw new ExecuteException("Command execution failed with exit code " + exitCode, exitCode);
        }
        
        return outputStream.toString().trim();
    }
}