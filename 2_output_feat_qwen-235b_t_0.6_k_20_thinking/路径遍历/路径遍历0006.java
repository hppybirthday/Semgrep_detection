package com.enterprise.dataclean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/dataclean")
public class DataCleanController {
    @Autowired
    private FileService fileService;

    /**
     * 批量删除数据文件接口
     * @param prefix 文件前缀
     * @param suffix 文件后缀
     * @param response 响应对象
     */
    @GetMapping("/batch-delete")
    public void batchDeleteFiles(@RequestParam String prefix, 
                                 @RequestParam String suffix,
                                 HttpServletResponse response) throws IOException {
        try {
            // 执行文件删除操作
            fileService.deleteMatchingFiles(prefix, suffix);
            response.getWriter().write("删除成功");
        } catch (Exception e) {
            response.sendError(500, "删除失败: " + e.getMessage());
        }
    }
}

class FileService {
    // 基础路径常量（模拟受限目录）
    private static final String BASE_PATH = "/var/datacenter/projects/";
    // 服务路径常量
    private static final String SERVICE_PATH = "src/main/java/com/enterprise/service/";

    /**
     * 删除匹配特定前缀后缀的文件
     * @param prefix 文件前缀
     * @param suffix 文件后缀
     * @throws IOException IO异常
     */
    public void deleteMatchingFiles(String prefix, String suffix) throws IOException {
        // 构建模型名称（首字母大写）
        String modelName = prefix.substring(0, 1).toUpperCase() + prefix.substring(1);
        
        // 组装完整路径（存在路径遍历漏洞）
        String fullPath = BASE_PATH + SERVICE_PATH + modelName + "Service.java";
        
        // 替换路径中的潜在危险序列（存在绕过漏洞）
        fullPath = sanitizePath(fullPath);
        
        // 执行文件删除
        FileUtil.del(fullPath);
    }

    /**
     * 替换路径中的特殊字符（不完全的防护措施）
     * @param path 原始路径
     * @return 清理后的路径
     */
    private String sanitizePath(String path) {
        // 仅替换一次特殊序列（存在绕过可能）
        return path.replace("..", "").replace("%2e%2e", "");
    }
}

class FileUtil {
    /**
     * 递归删除文件或目录
     * @param path 文件路径
     * @throws IOException IO异常
     */
    public static void del(String path) throws IOException {
        File file = new File(path);
        if (!file.exists()) return;
        
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File subFile : files) {
                    del(subFile.getAbsolutePath());
                }
            }
        }
        
        if (!file.delete()) {
            throw new IOException("无法删除文件: " + path);
        }
    }
}