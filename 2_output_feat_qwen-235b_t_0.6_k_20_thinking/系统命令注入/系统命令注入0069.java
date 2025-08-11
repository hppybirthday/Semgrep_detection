package com.example.app.upload;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    
    private final FileProcessor fileProcessor = new FileProcessor();

    @PostMapping("/process")
    public String handleUpload(@RequestParam String filename) {
        try {
            // 验证文件名格式
            if (!isValidFilenameFormat(filename)) {
                return "Invalid filename format";
            }
            
            // 处理文件并执行系统命令
            return fileProcessor.processAndExtract(filename);
            
        } catch (Exception e) {
            return "Processing failed: " + e.getMessage();
        }
    }

    private boolean isValidFilenameFormat(String filename) {
        // 简单验证文件名长度和扩展名
        return filename != null && filename.length() < 255 && 
               (filename.endsWith(".tar.gz") || filename.endsWith(".zip"));
    }
}

class FileProcessor {
    
    String processAndExtract(String filename) throws IOException, InterruptedException {
        String safePath = sanitizePath(filename);
        String[] command = buildExtractionCommand(safePath);
        
        ProcessBuilder pb = new ProcessBuilder(command);
        Process process = pb.start();
        
        // 读取命令输出
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

    private String sanitizePath(String path) {
        // 移除路径中的../防止路径遍历
        return path.replace("..", "");
    }

    private String[] buildExtractionCommand(String filename) {
        // 根据文件类型构建解压命令
        if (filename.endsWith(".tar.gz")) {
            return new String[]{"sh", "-c", "tar -xzf " + filename + " -C /tmp/extraction/"};
        } else {
            return new String[]{"sh", "-c", "unzip " + filename + " -d /tmp/extraction/"};
        }
    }
}