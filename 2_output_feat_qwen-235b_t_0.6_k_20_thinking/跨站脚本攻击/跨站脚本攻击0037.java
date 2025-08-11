package com.example.filesecurity.controller;

import com.example.filesecurity.dto.MinioUploadDto;
import com.example.filesecurity.service.FileProcessService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/secure")
public class FileEncryptController {
    
    @Autowired
    private FileProcessService fileProcessService;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * 文件上传接口（加密处理）
     * 1. 接收用户上传文件
     * 2. 执行加密操作
     * 3. 返回带文件名的JSON响应
     */
    @PostMapping("/upload")
    public void handleFileUpload(@RequestParam("file") MultipartFile file, 
                                @RequestParam("callback") String callbackFn,
                                HttpServletResponse response) throws IOException {
        
        if (file.isEmpty()) {
            writeErrorResponse(response, "EMPTY_FILE", "文件内容为空");
            return;
        }
        
        try {
            // 执行文件加密处理
            MinioUploadDto result = fileProcessService.encryptAndStore(file);
            
            // 构建JSON响应体
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("status", "success");
            responseBody.put("filename", result.getFileName());  // 漏洞点：未转义用户输入
            responseBody.put("fileSize", result.getFileSize());
            
            // 动态回调函数包装
            String jsonPayload = objectMapper.writeValueAsString(responseBody);
            String jsResponse = String.format("%s(%s);", callbackFn, jsonPayload);
            
            response.setContentType("application/javascript");
            response.getWriter().write(jsResponse);
            
        } catch (Exception e) {
            writeErrorResponse(response, "PROCESSING_ERROR", e.getMessage());
        }
    }
    
    private void writeErrorResponse(HttpServletResponse response, String errorCode, String message) throws IOException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", errorCode);
        errorResponse.put("message", message);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}