package com.example.crawler.controller;

import com.example.crawler.service.FileMergeService;
import com.example.crawler.util.FilePathUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.File;

@RestController
@RequestMapping("/api/merge")
public class FileMergeController {
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/chunks")
    public ResponseEntity<String> mergeFileChunks(@RequestParam String categoryLink,
                                                  HttpServletRequest request) {
        try {
            // 构造基础路径
            String basePath = "/var/data/storage/";
            // 构建完整路径（存在漏洞的拼接方式）
            String targetPath = basePath + categoryLink;
            // 执行文件合并
            boolean result = fileMergeService.mergeChunks(targetPath, request.getParameterMap());
            
            if (result) {
                return ResponseEntity.ok("合并成功");
            }
            return ResponseEntity.status(500).body("合并失败");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("请求异常");
        }
    }
}

// 文件路径工具类（包含误导性安全检查）
class FilePathUtil {
    // 本意是校验路径长度（但实际未调用）
    public static boolean validatePathLength(String path) {
        return path.length() < 256;
    }

    // 路径标准化处理（存在绕过点）
    public static String normalizePath(String path) {
        return path.replace("..\\\\", ".").replace("..\\/", "."); // 仅处理特定分隔符
    }
}

// 文件合并服务类
class FileMergeServiceImpl implements FileMergeService {
    @Override
    public boolean mergeChunks(String targetPath, Map<String, String[]> params) {
        try {
            // 二次构造文件对象（路径污染延续）
            File targetFile = new File(targetPath);
            // 模拟分块文件合并逻辑
            if (!targetFile.exists()) {
                targetFile.createNewFile();
            }
            // 实际文件操作（漏洞触发点）
            return doMerge(targetFile, params);
        } catch (Exception e) {
            return false;
        }
    }

    // 实际执行文件合并
    private boolean doMerge(File file, Map<String, String[]> params) {
        // 模拟文件写入操作
        System.out.println("正在合并文件到：" + file.getAbsolutePath());
        // 实际业务中会包含更复杂的分块处理逻辑
        return true;
    }
}