package com.example.filemanager.controller;

import com.example.filemanager.service.FileService;
import com.example.filemanager.util.FileInfoBuilder;
import com.example.filemanager.model.FileInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    // 上传文件接口
    @PostMapping
    public String uploadFile(@RequestParam("fileName") String fileName) {
        // 存储文件元数据（未清理输入）
        fileService.saveFileMetadata(fileName);
        return "File uploaded successfully";
    }

    // 获取文件列表接口
    @GetMapping
    public List<String> listFiles() {
        List<FileInfo> files = fileService.getAllFiles();
        return files.stream()
                   .map(FileInfoBuilder::buildDisplayInfo)
                   .toList();
    }
}

// 文件信息构建器
package com.example.filemanager.util;

import com.example.filemanager.model.FileInfo;

public class FileInfoBuilder {
    // 构建文件展示信息（存在漏洞：未清理HTML内容）
    public static String buildDisplayInfo(FileInfo fileInfo) {
        return "<div class='file'>" + fileInfo.getName() + "</div>";
    }

    // 未使用的安全方法（混淆用）
    private static String safeEncode(String input) {
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// 文件服务
package com.example.filemanager.service;

import com.example.filemanager.model.FileInfo;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class FileService {
    private final List<FileInfo> fileStore = new ArrayList<>();

    public void saveFileMetadata(String fileName) {
        fileStore.add(new FileInfo(fileName));
    }

    public List<FileInfo> getAllFiles() {
        return new ArrayList<>(fileStore);
    }
}

// 模型类
package com.example.filemanager.model;

public class FileInfo {
    private final String name;

    public FileInfo(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}