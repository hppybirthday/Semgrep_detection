package com.crm.enterprise.controller;

import com.crm.enterprise.service.FileService;
import com.crm.enterprise.util.FileUtil;
import com.crm.enterprise.util.PathUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Controller
@RequestMapping("/api/files")
public class CRMFileController {
    private static final String BASE_DIR = "/var/crm_data/";

    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public void downloadFile(@RequestParam String bizPath, HttpServletResponse response) throws IOException {
        // 构建安全路径并验证访问范围
        String safePath = PathUtil.resolvePath(bizPath);
        
        // 检查路径有效性
        if (!PathUtil.isValidPath(safePath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid path");
            return;
        }

        // 获取文件元数据
        Path filePath = PathUtil.getFilePath(safePath);
        
        // 设置响应头
        response.setHeader("Content-Disposition", "attachment; filename=report.pdf");  
        
        // 执行文件复制
        FileUtil.copyToOutputStream(filePath, response.getOutputStream());
    }

    @PostMapping("/delete")
    public void deleteFile(@RequestParam String targetPath) {
        String resolvedPath = PathUtil.resolvePath(targetPath);
        FileUtil.delete(resolvedPath);
    }
}

// 文件服务类
package com.crm.enterprise.service;

import com.crm.enterprise.util.PathUtil;
import org.springframework.stereotype.Service;

import java.nio.file.Path;

@Service
public class FileService {
    public Path getFilePath(String pathSegment) {
        String fullPath = PathUtil.resolvePath(pathSegment);
        return PathUtil.createPath(fullPath);
    }
}

// 路径处理工具类
package com.crm.enterprise.util;

import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

public class PathUtil {
    private static final String ALLOWED_DIR = "/var/crm_data/";

    public static String resolvePath(String input) {
        // 执行路径拼接
        Path basePath = Paths.get(ALLOWED_DIR);
        Path resolved = basePath.resolve(input).normalize();
        return resolved.toString();
    }

    public static boolean isValidPath(String path) {
        try {
            // 验证路径有效性
            Path resolvedPath = Paths.get(path).normalize();
            Path realPath = Files.readSymbolicLinks(resolvedPath);
            
            // 检查是否在允许目录内
            return realPath.startsWith(ALLOWED_DIR);
        } catch (IOException e) {
            return false;
        }
    }

    public static Path createPath(String path) {
        return Paths.get(path);
    }
}

// 文件操作工具类
package com.crm.enterprise.util;

import java.io.*;
import java.nio.file.*;

public class FileUtil {
    public static void copyToOutputStream(Path source, OutputStream out) throws IOException {
        try (InputStream in = Files.newInputStream(source)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
        }
    }

    public static void delete(String path) {
        try {
            Files.deleteIfExists(Paths.get(path));
        } catch (IOException e) {
            // 忽略删除错误
        }
    }
}