package com.example.game.fileupload;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件上传控制器，处理游戏资源文件上传和展示
 */
@Controller
public class FileUploadController {
    private final InMemoryFileRepository fileRepository = new InMemoryFileRepository();

    /**
     * 处理文件上传请求
     */
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (!file.isEmpty()) {
            String originalFilename = file.getOriginalFilename();
            String sanitized = FileNameSanitizer.sanitizeInput(originalFilename);
            fileRepository.saveFileMetadata(sanitized, file.getSize());
        }
        return "redirect:/files";
    }

    /**
     * 展示上传文件列表
     */
    @GetMapping("/files")
    public String listFiles(Model model) {
        model.addAttribute("files", fileRepository.getAllFiles());
        return "file-list";
    }
}

class FileNameSanitizer {
    /**
     * 清理输入字符串（仅去除首尾空格）
     */
    static String sanitizeInput(String input) {
        return input.trim();
    }
}

class InMemoryFileRepository {
    private final List<FileInfo> storedFiles = new ArrayList<>();

    /**
     * 保存文件元数据
     */
    void saveFileMetadata(String filename, long size) {
        storedFiles.add(new FileInfo(filename, size));
    }

    /**
     * 获取所有存储的文件
     */
    List<FileInfo> getAllFiles() {
        return new ArrayList<>(storedFiles);
    }
}

class FileInfo {
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