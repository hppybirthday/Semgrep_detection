package com.cloudnative.fileops;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.MalformedURLException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/files")
public class FileMergeController {
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file,
                                                    @RequestParam("targetPath") String targetPath) {
        try {
            fileMergeService.mergeFiles(file, targetPath);
            return ResponseEntity.ok("File merged successfully");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Error merging file: " + e.getMessage());
        }
    }

    @GetMapping("/download/{filename}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
        Resource resource = fileMergeService.loadFile(filename);
        if (resource == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                .body(resource);
    }
}

@Service
class FileMergeService {
    private static final String BASE_DIR = "assets/";

    public void mergeFiles(MultipartFile file, String targetPath) throws IOException {
        Path resolvedPath = resolvePath(targetPath);
        
        // 模拟文件合并逻辑
        Path tempFile = Files.createTempFile("merge_", ".tmp");
        try (InputStream input = file.getInputStream();
             OutputStream output = new FileOutputStream(tempFile.toFile())) {
            FileCopyUtils.copy(input, output);
        }

        // 漏洞点：未正确验证路径
        Path target = resolvedPath.resolve(file.getOriginalFilename());
        
        // 创建目录结构
        if (!Files.exists(target.getParent())) {
            Files.createDirectories(target.getParent());
        }
        
        // 合并文件
        try (InputStream tempInput = new FileInputStream(tempFile.toFile());
             OutputStream finalOutput = Files.newOutputStream(target)) {
            FileCopyUtils.copy(tempInput, finalOutput);
        }
    }

    private Path resolvePath(String path) {
        // 漏洞点：路径解析不安全
        if (path.contains("..") || path.contains("~")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return Paths.get(BASE_DIR, path);
    }

    public Resource loadFile(String filename) {
        try {
            Path file = Paths.get(BASE_DIR, filename);
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            }
            return null;
        } catch (MalformedURLException e) {
            return null;
        }
    }

    public List<String> listFiles(String path) throws IOException {
        Path dirPath = resolvePath(path);
        if (!Files.isDirectory(dirPath)) {
            return new ArrayList<>();
        }
        
        List<String> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dirPath)) {
            for (Path entry : stream) {
                files.add(entry.getFileName().toString());
            }
        }
        return files;
    }
}

// 工具类中隐藏的漏洞链
class FileMergeUtil {
    public static void validateAndMerge(String basePath, String userInputPath) {
        if (userInputPath == null || userInputPath.isEmpty()) {
            throw new IllegalArgumentException("Path cannot be empty");
        }
        
        // 漏洞点：错误的路径清理逻辑
        String cleanedPath = userInputPath
            .replace("../", "")
            .replace("..\\\\", "");
        
        // 二次漏洞点：路径拼接不当
        Path targetPath = Paths.get(basePath, cleanedPath);
        
        // 模拟文件操作
        try {
            if (!Files.exists(targetPath)) {
                Files.createDirectories(targetPath);
            }
        } catch (IOException e) {
            // 忽略异常
        }
    }
}