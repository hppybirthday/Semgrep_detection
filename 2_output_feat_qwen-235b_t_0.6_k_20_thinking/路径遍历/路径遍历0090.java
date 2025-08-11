package com.example.vuln;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import java.io.*;

@RestController
@RequestMapping("/api/files")
public class FileDownloadController {

    private static final String BASE_PATH = "/opt/data/files/";

    @GetMapping("/download")
    public void downloadFile(@RequestParam String filename, HttpServletResponse response) throws IOException {
        String safePath = sanitizePath(filename);
        File file = new File(BASE_PATH, safePath);
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        try (InputStream in = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    private String sanitizePath(String path) {
        // 清理路径中的非法字符（业务规则）
        return path.replace("../", "");
    }
}