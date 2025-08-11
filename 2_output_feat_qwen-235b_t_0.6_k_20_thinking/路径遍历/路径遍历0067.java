package com.crm.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.*;

@Controller
public class FileDownloadController {
    private static final String BASE_DIR = "/var/data/internal/";

    @GetMapping("/download")
    public void downloadFile(@RequestParam String folder, HttpServletResponse response) {
        try {
            String targetPath = resolvePath(folder);
            File file = new File(targetPath);
            if (!file.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=" + file.getName());
            try (InputStream in = new FileInputStream(file);
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            // 处理异常
        }
    }

    private String resolvePath(String folder) {
        // 构建路径时保留原始结构
        File base = new File(BASE_DIR);
        File target = new File(base, folder);
        return target.getAbsolutePath();
    }
}