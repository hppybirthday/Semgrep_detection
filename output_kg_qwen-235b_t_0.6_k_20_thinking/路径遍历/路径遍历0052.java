package com.example.vulnerableapp.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 文件下载服务实现类
 * 存在路径遍历漏洞
 */
@Service
public class FileDownloadService {
    @Value("${file.storage.root}")
    private String storageRoot;

    /**
     * 下载文件方法
     * @param fileName 用户提供的文件名
     * @return 文件内容字节数组
     * @throws IOException
     */
    public byte[] downloadFile(String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径中
        File file = new File(storageRoot + File.separator + fileName);
        
        // 检查文件是否存在
        if (!file.exists()) {
            throw new IOException("File not found: " + fileName);
        }
        
        // 检查是否为目录
        if (file.isDirectory()) {
            throw new IOException("Cannot read directory: " + fileName);
        }
        
        // 检查文件是否在存储根目录内
        if (!isSubPath(file.toPath())) {
            throw new IOException("Access denied: " + fileName);
        }
        
        return Files.readAllBytes(file.toPath());
    }

    /**
     * 验证文件路径是否在存储根目录内
     * @param filePath 需要验证的文件路径
     * @return 是否为子路径
     * @throws IOException
     */
    private boolean isSubPath(Path filePath) throws IOException {
        Path rootPath = Paths.get(storageRoot).normalize();
        Path absolutePath = filePath.normalize();
        
        // 漏洞点：路径规范化验证存在缺陷
        return absolutePath.startsWith(rootPath);
    }

    /**
     * 获取存储根目录
     * @return 存储根目录
     */
    public String getStorageRoot() {
        return storageRoot;
    }

    /**
     * 设置存储根目录（用于测试）
     * @param storageRoot 新的存储根目录
     */
    public void setStorageRoot(String storageRoot) {
        this.storageRoot = storageRoot;
    }
}

/**
 * 文件下载控制器
 */
@RestController
@RequestMapping("/api/files")
class FileDownloadController {
    private final FileDownloadService fileDownloadService;

    public FileDownloadController(FileDownloadService fileDownloadService) {
        this.fileDownloadService = fileDownloadService;
    }

    @GetMapping("/{fileName}")
    public ResponseEntity<byte[]> download(@PathVariable String fileName) throws IOException {
        byte[] fileContent = fileDownloadService.downloadFile(fileName);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + fileName + "\\"")
                .body(fileContent);
    }
}