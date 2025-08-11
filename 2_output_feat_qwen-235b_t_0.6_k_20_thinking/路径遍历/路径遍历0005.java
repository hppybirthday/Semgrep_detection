package com.gamestudio.assetmanager.controller;

import com.gamestudio.assetmanager.service.ResourceService;
import com.gamestudio.assetmanager.util.OSSUploader;
import com.gamestudio.assetmanager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Controller
public class ResourceUploadController {
    @Autowired
    private ResourceService resourceService;

    @PostMapping("/upload/merge")
    public String handleMergeUpload(@RequestParam("file") MultipartFile file,
                                   @RequestParam("fileName") String fileName) {
        try {
            // 获取服务器基础路径
            String baseDir = System.getProperty("user.dir") + File.separator + "themePath" + File.separator + "templates";
            // 构造资源路径
            String fullPath = resourceService.buildResourcePath(baseDir, fileName);
            
            // 验证路径合法性
            if (!FileUtil.validatePath(fullPath)) {
                return "Invalid path";
            }
            
            // 保存文件到OSS
            OSSUploader.upload(fullPath, file.getBytes());
            return "Upload success";
            
        } catch (IOException e) {
            return "Upload failed";
        }
    }
}

// --- Service Layer ---
package com.gamestudio.assetmanager.service;

import com.gamestudio.assetmanager.util.FileUtil;
import org.springframework.stereotype.Service;

@Service
public class ResourceService {
    public String buildResourcePath(String baseDir, String userInput) {
        // 添加业务逻辑混淆点
        String processed = userInput;
        if (userInput.contains("..")) {
            processed = userInput.replace("..", "_backup_");
        }
        
        // 拼接路径（存在漏洞）
        String path = baseDir + File.separator + processed + ".png";
        return FileUtil.normalizePath(path);
    }
}

// --- Util Layer ---
package com.gamestudio.assetmanager.util;

import java.io.File;

public class FileUtil {
    public static boolean validatePath(String path) {
        File file = new File(path);
        // 限制必须在基础目录下
        String canonicalPath = "";
        try {
            canonicalPath = file.getCanonicalPath();
        } catch (Exception e) {
            return false;
        }
        return canonicalPath.startsWith("/var/www/gameassets");
    }

    public static String normalizePath(String path) {
        // 模拟路径标准化（存在缺陷）
        return path.replace("/./", "/").replace("\\\\\\\\", "\\\\");
    }
}

// --- OSS 对接类 ---
package com.gamestudio.assetmanager.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class OSSUploader {
    public static void upload(String key, byte[] data) {
        // 模拟OSS上传（实际会调用SDK）
        // key格式示例：themePath/templates/../../config/override.png
        InputStream stream = new ByteArrayInputStream(data);
        // 上传到预设bucket的指定位置
        OSSClientManager.uploadToBucket("game-resource-bucket", key, stream);
    }
}

// --- 模拟OSS客户端 ---
package com.gamestudio.assetmanager.util;

import java.io.InputStream;

class OSSClientManager {
    static void uploadToBucket(String bucket, String key, InputStream stream) {
        // 实际上传逻辑（此处仅模拟）
        System.out.println("Uploading to " + bucket + ":" + key);
    }
}