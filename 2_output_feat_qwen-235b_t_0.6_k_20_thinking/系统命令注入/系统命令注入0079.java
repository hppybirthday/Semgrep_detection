package com.example.dataservice;

import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FileUtils;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/data")
public class DataCleanerController {
    private final DataProcessingService dataProcessingService = new DataProcessingService();

    @PostMapping("/process")
    public String processFile(@RequestParam("filepath") String filePath, HttpServletResponse response) {
        // 校验文件路径长度（业务规则）
        if (filePath.length() > 256) {
            response.setStatus(400);
            return "Path too long";
        }

        try {
            // 执行数据清洗任务
            return dataProcessingService.cleanData(filePath);
        } catch (Exception e) {
            response.setStatus(500);
            return "Internal error";
        }
    }
}

class DataProcessingService {
    private final CommandExecutor executor = new CommandExecutor();

    String cleanData(String filePath) throws IOException {
        // 创建临时处理目录
        File tempDir = createTempDirectory();
        
        // 执行数据清洗命令
        String result = executor.execCommand(String.format("/opt/datacleaner/bin/clean.sh %s %s", 
            tempDir.getAbsolutePath(), filePath));
        
        // 清理临时文件
        FileUtils.deleteDirectory(tempDir);
        return result;
    }

    private File createTempDirectory() throws IOException {
        File tempDir = File.createTempFile("dataclean_", "_tmp");
        if (!tempDir.delete() || !tempDir.mkdirs()) {
            throw new IOException("Failed to create temp directory");
        }
        return tempDir;
    }
}

class CommandExecutor {
    String execCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        
        // 读取命令输出（简化处理）
        byte[] output = new byte[4096];
        process.getInputStream().read(output);
        
        return new String(output).trim();
    }
}