package com.chatapp.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/files")
public class ChatFileUploadController {
    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private SystemConfigService systemConfigService;

    // 上传接口允许用户指定存储路径
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                           @RequestParam("path") String path,
                           @RequestParam("category") String categoryPinyin) {
        try {
            String storedPath = fileStorageService.storeFile(path, categoryPinyin, file);
            return String.format("File stored at: %s", storedPath);
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    // 删除接口接收路径列表执行删除
    @PostMapping("/delete")
    public String deleteFiles(@RequestParam("paths") List<String> paths) {
        try {
            systemConfigService.deleteFileByPathList(paths);
            return "Files deleted successfully";
        } catch (Exception e) {
            return "Delete failed: " + e.getMessage();
        }
    }
}

class FileStorageService {
    private final String BASE_DIR = "/var/chatapp/uploads";

    // 根据分类拼音构造存储路径
    String constructFilePath(String prefix, String categoryPinyin, String filename) {
        // 多层拼接隐藏漏洞点
        String categoryPath = prefix + "/" + categoryPinyin;
        String fullPath = categoryPath + "/" + filename;
        return fullPath;
    }

    public String storeFile(String path, String categoryPinyin, MultipartFile file) throws IOException {
        // 二次拼接路径
        String safePath = sanitizePath(path);
        String storagePath = constructFilePath(safePath, categoryPinyin, file.getOriginalFilename());
        
        // 看似安全的文件类型检查（实际无效）
        if (!isValidExtension(file.getOriginalFilename())) {
            throw new IllegalArgumentException("Invalid file type");
        }

        File dest = new File(storagePath);
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(file.getBytes());
        }
        return storagePath;
    }

    // 误导性的路径清理方法
    private String sanitizePath(String path) {
        return path.replace("..", ""); // 仅替换字符串不生效
    }

    private boolean isValidExtension(String filename) {
        String[] allowed = {"jpg", "png", "txt"};
        String ext = filename.substring(filename.lastIndexOf(".") + 1);
        for (String a : allowed) {
            if (a.equalsIgnoreCase(ext)) return true;
        }
        return false;
    }
}

class SystemConfigService {
    // 批量删除路径的危险方法
    public void deleteFileByPathList(List<String> paths) throws IOException {
        for (String path : paths) {
            File file = new File(path);
            if (file.exists()) {
                // 记录删除日志（看似有审计）
                System.out.println("Deleting file: " + path);
                boolean deleted = file.delete();
                if (!deleted) throw new IOException("Delete failed");
            }
        }
    }
}