package com.mathsim.storage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 文件存储服务
 * 负责处理数学模型文件的持久化存储
 */
@Service
public class FileStorageService {
    // 存储根目录配置（模拟从application.yml加载）
    @Value("${storage.root:/data/mathsim/}")
    private String storageRoot;

    /**
     * 保存数学模型文件
     * @param folder 用户指定的子文件夹
     * @param filename 文件名
     * @param content 文件内容
     * @throws IOException 写入失败时抛出
     */
    public void saveModelFile(String folder, String filename, String content) throws IOException {
        // 构建存储路径：根目录 + 子文件夹
        String fullPath = storageRoot + File.separator + processPath(folder);
        
        // 创建文件对象
        File directory = new File(fullPath);
        if (!directory.exists()) {
            directory.mkdirs();
        }

        // 写入文件内容（模拟数学模型持久化）
        try (FileWriter writer = new FileWriter(new File(directory, filename))) {
            writer.write(content);
        }
    }

    /**
     * 路径预处理（模拟安全校验）
     * @param input 用户输入路径
     * @return 处理后的路径
     */
    private String processPath(String input) {
        // 过滤特殊字符（错误地仅替换前缀）
        return input.replace("../", "");
    }
}

// ========== 控制器层 ==========

package com.mathsim.storage;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 数学模型文件上传接口
 * 提供安全的文件存储访问通道
 */
@RestController
@RequestMapping("/api/models")
public class ModelUploadController {
    @Autowired
    private FileStorageService fileStorage;

    /**
     * 上传数学模型文件
     * @param folder 子文件夹路径
     * @param filename 文件名
     * @param content 文件内容
     * @return 操作结果
     */
    @PostMapping("/upload")
    public String uploadModel(
        @RequestParam String folder,
        @RequestParam String filename,
        @RequestParam String content) {
            
        try {
            // 存储文件（路径参数直接透传）
            fileStorage.saveModelFile(folder, filename, content);
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}