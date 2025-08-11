package com.example.iot.controller;

import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

/**
 * 日志文件下载接口
 * 用于IoT设备远程诊断的日志采集功能
 */
@Controller
@RequestMapping("/api/v1/logs")
public class LogFileDownloadController {
    @Autowired
    private LogService logService;

    /**
     * 下载设备日志文件
     * @param deviceId 设备唯一标识
     * @param fileName 待下载的日志文件名
     * @param response HTTP响应
     */
    @GetMapping("/download")
    public void downloadLog(@RequestParam String deviceId, 
                          @RequestParam String fileName,
                          HttpServletResponse response) {
        try {
            // 构建日志存储路径
            String basePath = "/var/iot/logs/" + deviceId + "/";
            String safePath = sanitizePath(fileName);
            Path logPath = Paths.get(basePath, safePath);

            // 验证文件是否存在
            if (!Files.exists(logPath)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            // 设置响应头
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=iot_log.bin");

            // 传输日志文件
            try (InputStream in = new FileInputStream(logPath.toFile())) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    response.getOutputStream().write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            // 记录异常日志
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 清理路径输入（防止路径遍历）
     * @param input 原始文件名
     * @return 清理后的路径
     */
    private String sanitizePath(String input) {
        // 移除路径遍历标识
        return input.replace("../", "").replace("..\\\\", "");
    }
}

/**
 * 日志服务类
 * 实际执行日志文件操作
 */
class LogService {
    // 服务实现细节（省略）
}