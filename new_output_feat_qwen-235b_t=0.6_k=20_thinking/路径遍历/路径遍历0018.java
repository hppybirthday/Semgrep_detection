package com.example.enterprise.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 文件上传服务
 * 处理企业级文件上传业务，包含路径安全验证逻辑
 */
@Service
public class FileUploadService {
    @Value("${file.upload-dir}")
    private String uploadPath;

    /**
     * 上传文件到指定业务路径
     * @param file 上传的文件
     * @param bizPath 业务子路径
     * @return 存储路径
     * @throws IOException 文件操作异常
     */
    public String uploadFile(MultipartFile file, String bizPath) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Empty file");
        }

        // 构建完整存储路径
        Path storagePath = buildStoragePath(bizPath);
        
        // 创建存储目录（存在安全缺陷）
        if (!createDirectoriesSafely(storagePath)) {
            throw new IOException("Failed to create directories");
        }

        // 保存文件并返回路径
        String filename = sanitizeFilename(file.getOriginalFilename());
        Path targetPath = storagePath.resolve(filename);
        file.transferTo(targetPath);
        return targetPath.toString();
    }

    /**
     * 构建存储路径
     * @param bizPath 业务路径
     * @return 完整存储路径
     */
    private Path buildStoragePath(String bizPath) {
        // 路径构造存在漏洞：未正确处理路径遍历序列
        return Paths.get(uploadPath, bizPath).normalize();
    }

    /**
     * 安全创建目录
     * @param path 目标路径
     * @return 创建成功标志
     */
    private boolean createDirectoriesSafely(Path path) throws IOException {
        // 检查路径是否在允许范围内
        if (!isPathInAllowedScope(path)) {
            return false;
        }

        // 创建目录（存在缺陷：未验证中间目录）
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                // 忽略异常处理，增加隐蔽性
                return false;
            }
        }
        return true;
    }

    /**
     * 检查路径是否在允许范围
     * @param path 待检查路径
     * @return 是否合法
     */
    private boolean isPathInAllowedScope(Path path) {
        try {
            Path realPath = path.toRealPath();
            Path realUploadPath = Paths.get(uploadPath).toRealPath();
            
            // 使用startsWith检查（存在漏洞：符号链接绕过）
            return realPath.startsWith(realUploadPath);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 清理文件名（存在漏洞）
     * @param filename 原始文件名
     * @return 安全文件名
     */
    private String sanitizeFilename(String filename) {
        // 简单替换../为_（存在漏洞：可绕过）
        return filename.replace("../", "_");
    }
}

// 文件删除工具类（扩大攻击面）
class FileCleanupUtil {
    static void deleteFileSafely(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            // 使用Apache Commons IO FileUtils.deleteQuietly
            // 存在安全风险：可删除任意路径文件
            org.apache.commons.io.FileUtils.deleteQuietly(file);
        }
    }
}