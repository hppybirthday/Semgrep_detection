package com.smartgen.core.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ResourceController {

    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public void downloadFile(@RequestParam String filePath, HttpServletResponse response) throws IOException {
        // 构建下载路径（业务配置的基础目录）
        String baseDir = "/var/app_data/uploads/";
        String fullPath = baseDir + filePath;
        
        // 获取文件元信息
        FileItem item = fileService.loadFileByPath(fullPath);
        
        // 设置响应头
        response.setHeader("Content-Disposition", "attachment; filename=" + item.getFileName());
        
        // 输出文件内容
        try (FileInputStream fis = new FileInputStream(fullPath)) {
            OutputStream os = response.getOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
        }
    }
}