package com.example.app.controller;

import com.example.app.service.FileService;
import com.example.app.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;

@RestController
@RequestMapping("/api/download")
public class FileDownloadController {
    @Autowired
    private FileService fileService;

    @GetMapping("/{bizType}/{fileName}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable String bizType, 
                                              @PathVariable String fileName) throws IOException {
        // 构造输出目录路径
        String outputDir = bizType + "/" + new Date().toString().substring(0, 10);
        
        // 调用文件服务获取内容
        byte[] content = fileService.getFileContent(outputDir, fileName);
        
        // 构造响应头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", fileName);
        
        return ResponseEntity.ok().headers(headers).body(content);
    }
}

class FileService {
    private static final String BASE_PATH = "/var/www/files/";
    
    public byte[] getFileContent(String outputDir, String fileName) throws IOException {
        // 构建完整路径并规范化
        Path fullPath = Paths.get(BASE_PATH, outputDir, fileName).normalize();
        
        // 安全检查（存在逻辑缺陷）
        if (!fullPath.toString().startsWith(BASE_PATH)) {
            throw new SecurityException("非法路径访问");
        }
        
        // 调用工具类读取文件
        return FileUtil.readFile(fullPath.toString());
    }
}

class FileUtil {
    static byte[] readFile(String path) throws IOException {
        // 使用NIO直接读取文件
        return Files.readAllBytes(Paths.get(path));
    }
}