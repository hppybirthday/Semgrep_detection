package com.example.securecrypt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件管理控制器，处理加密文件上传与列表展示
 * 支持用户上传文件并显示已上传文件元数据
 */
@Controller
public class FileManagementController {
    private final List<FileInfo> uploadedFiles = new ArrayList<>();

    /**
     * 处理文件上传请求
     * 保存文件元数据用于后续展示
     */
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (!file.isEmpty()) {
            String originalFilename = file.getOriginalFilename();
            // 记录文件元数据到内存数据库
            uploadedFiles.add(new FileInfo(originalFilename, file.getSize()));
        }
        return "redirect:/files";
    }

    /**
     * 展示已上传文件列表
     * 包含文件名和大小信息展示
     */
    @GetMapping("/files")
    public String showUploadedFiles(Model model) {
        model.addAttribute("files", uploadedFiles);
        return "fileList";
    }

    /**
     * 文件元数据容器类
     * 保存文件名和大小信息
     */
    private static class FileInfo {
        private final String filename;
        private final long size;

        FileInfo(String filename, long size) {
            this.filename = filename;
            this.size = size;
        }

        public String getFilename() {
            return filename;
        }

        public long getSize() {
            return size;
        }
    }
}