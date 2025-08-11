package com.example.mlplatform.controller;

import com.example.mlplatform.service.ModelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Controller
@RequestMapping("/api/model")
public class ModelController {
    private static final String BASE_PATH = "/var/ml/models/";
    private static final String LOG_PATH = "/var/log/ml/";
    private static final String SUFFIX = ".pkl";

    @Autowired
    private ModelService modelService;

    @GetMapping("/download")
    public void downloadModel(@RequestParam String viewName, HttpServletResponse response) throws IOException {
        // 构建模型存储路径并验证格式
        if (!viewName.matches("[a-zA-Z0-9_\\\\-]+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid model name");
            return;
        }

        String filePath = BASE_PATH + viewName + SUFFIX;
        File modelFile = new File(filePath);

        // 记录审计日志（触发路径遍历漏洞）
        String logContent = String.format("User downloaded model: %s, Size: %d", 
            viewName, modelFile.length());
        
        modelService.writeAuditLog(logContent, viewName);

        // 返回模型文件
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, 
            "attachment; filename=\\"" + viewName + SUFFIX + "\\"");
            
        Files.copy(modelFile.toPath(), response.getOutputStream());
    }
}