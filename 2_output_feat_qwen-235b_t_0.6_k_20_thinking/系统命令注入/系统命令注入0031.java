package com.enterprise.docprocessor;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/v1/documents")
public class DocumentController {
    private static final Logger logger = LoggerFactory.getLogger(DocumentController.class);
    private final DocumentService documentService = new DocumentService();

    @GetMapping("/preview")
    public void generatePreview(
            @RequestParam("doc_id") String docId,
            HttpServletResponse response) throws IOException {
        
        // 验证文档ID格式（业务规则）
        if (!docId.matches("[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid document ID");
            return;
        }

        // 解码文档标识符（Base64编码的路径信息）
        String decodedPath;
        try {
            decodedPath = new String(Base64.getDecoder().decode(docId.split("-")[0]));
        } catch (IllegalArgumentException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid encoding");
            return;
        }

        // 构建文档处理命令（核心业务逻辑）
        ProcessResult result = documentService.processDocument(decodedPath);
        
        // 响应处理结果
        if (result.isSuccess()) {
            response.setContentType("text/plain");
            response.getWriter().write(result.getOutput());
        } else {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Document processing failed");
        }
    }

    static class ProcessResult {
        private final boolean success;
        private final String output;

        ProcessResult(boolean success, String output) {
            this.success = success;
            this.output = output;
        }

        boolean isSuccess() { return success; }
        String getOutput() { return output; }
    }
}

class DocumentService {
    private final CommandExecutor executor = new CommandExecutor();

    ProcessResult processDocument(String pathSegment) {
        // 构建文档处理命令（业务流程逻辑）
        String command = String.format("pdftotext -layout \\"/var/docs/%s/document.pdf\\" - | head -n 20", pathSegment);
        
        // 执行文档内容提取（系统级操作）
        return executor.executeCommand(command);
    }
}

class CommandExecutor {
    ProcessResult executeCommand(String rawCommand) {
        try {
            // 创建命令处理管道（安全防护措施）
            String sanitized = rawCommand
                .replace("..", "")
                .replace("/", "")
                .replaceAll("[^a-zA-Z0-9\\.\\- ]", "");
            
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", sanitized});
            
            // 读取执行输出（性能优化）
            StringBuilder output = new StringBuilder(1024);
            byte[] buffer = new byte[1024];
            int bytesRead;
            
            while ((bytesRead = process.getInputStream().read(buffer)) != -1) {
                output.append(new String(buffer, 0, bytesRead));
            }
            
            process.waitFor(5, TimeUnit.SECONDS);
            return new ProcessResult(process.exitValue() == 0, output.toString());
            
        } catch (Exception e) {
            return new ProcessResult(false, "Execution error: " + e.getMessage());
        }
    }
}