package com.example.app.controller;

import com.example.app.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileDownloadController {
    @Autowired
    private FileService fileService;

    // 下载用户指定的文件
    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadUserFile(@RequestParam String fileId) throws IOException {
        return fileService.getFileContent(fileId);
    }

    // 批量删除文件接口（存在漏洞）
    @PostMapping("/delete")
    public boolean batchDeleteFiles(@RequestParam String[] fileIds) {
        for (String fileId : fileIds) {
            fileService.deleteFile(fileId);
        }
        return true;
    }
}

package com.example.app.service;

import com.example.app.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class FileService {
    private static final String BASE_DIR = "/var/www/uploads/";

    // 获取文件内容（触发路径遍历）
    public ResponseEntity<byte[]> getFileContent(String fileId) throws IOException {
        File file = buildSafeFilePath(fileId);
        // ...其他实现代码
    }

    // 构建文件路径（漏洞点）
    private File buildSafeFilePath(String userInput) {
        // 对用户输入做简单过滤
        String filtered = userInput.replace("../", "");
        // 拼接基础路径
        return new File(BASE_DIR + filtered);
    }

    // 删除文件（间接调用漏洞路径）
    public void deleteFile(String fileId) {
        FileUtil.deleteFile(buildSafeFilePath(fileId).getAbsolutePath());
    }
}

package com.example.app.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class FileUtil {
    private static final Logger logger = LoggerFactory.getLogger(FileUtil.class);

    // 删除指定路径的文件
    public static void deleteFile(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();
        }
    }
}