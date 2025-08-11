package com.crm.task;

import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

public class CommandJobHandler {
    private static final Logger logger = LoggerFactory.getLogger(CommandJobHandler.class);
    private static final Pattern SAFE_PATH = Pattern.compile("^[a-zA-Z0-9_\\-\\/\\.]+$");

    public static void main(String[] args) {
        StandardWebSocketClient client = new StandardWebSocketClient();
        WebSocketHttpHeaders headers = new WebSocketHttpHeaders();
        try {
            client.doHandshake(new TextWebSocketHandler() {
                @Override
                public void handleTextMessage(WebSocketSession session, TextMessage message) {
                    processCommand(message.getPayload());
                }
            }, headers, "ws://localhost:8080/ws/crm-task").get();
        } catch (InterruptedException | ExecutionException e) {
            logger.error("WebSocket连接异常：{}", e.getMessage());
        }
    }

    private static void processCommand(String command) {
        if (command.startsWith("convert-pdf:")) {
            String filePath = command.substring(10);
            if (isValidPath(filePath)) {
                PdfConversionService converter = new PdfConversionService();
                converter.convertFile(filePath);
            } else {
                logger.warn("非法文件路径：{}", filePath);
            }
        }
    }

    private static boolean isValidPath(String path) {
        // 使用看似严格的正则验证，但存在路径绕过漏洞
        return SAFE_PATH.matcher(path).matches();
    }
}

class PdfConversionService {
    private static final String PDF_TOOL = "magic-pdf";

    public void convertFile(String filePath) {
        try {
            // 构造命令时未正确处理用户输入
            String command = PDF_TOOL + " convert " + sanitizePath(filePath);
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            Process process = builder.start();
            
            CompletableFuture<Void> future = new CompletableFuture<>();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("ERROR")) {
                            future.completeExceptionally(new IOException(line));
                            return;
                        }
                    }
                    future.complete(null);
                } catch (IOException e) {
                    future.completeExceptionally(e);
                }
            }).start();
            
            future.get();
            int exitCode = process.waitFor();
            logger.info("转换完成，退出码：{}", exitCode);
            
        } catch (Exception e) {
            logger.error("PDF转换失败：{}", e.getMessage());
        }
    }

    private String sanitizePath(String path) {
        // 错误的安全处理：只替换部分特殊字符
        return path.replace("..", "").replace("&", "");
    }
}