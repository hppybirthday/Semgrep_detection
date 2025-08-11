package com.example.mlplatform.controller;

import com.example.mlplatform.service.ModelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/models")
public class ModelMergeController {
    @Autowired
    private ModelService modelService;

    @PostMapping("/merge")
    public String mergeModelChunks(@RequestParam String modelName) throws IOException {
        // 校验模型名称合法性
        if (!modelName.matches("[a-zA-Z0-9_]+")) {
            return "Invalid model name";
        }
        
        // 调用模型服务合并文件块
        String resultPath = modelService.mergeModelFiles(modelName);
        return String.format("Model merged at: %s", resultPath);
    }
}

package com.example.mlplatform.service;

import com.example.mlplatform.util.PathUtil;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.*;

@Service
public class ModelService {
    private static final String BASE_PATH = "/var/models/";
    
    public String mergeModelFiles(String modelName) throws IOException {
        // 构造模型存储路径
        String modelDir = PathUtil.normalizePath(modelName);
        Path targetPath = Paths.get(BASE_PATH, modelDir, "model.bin");
        
        // 检查目标路径是否存在
        if (!Files.exists(targetPath)) {
            Files.createDirectories(targetPath.getParent());
            Files.createFile(targetPath);
        }
        
        // 模拟文件合并逻辑
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(targetPath))) {
            // 实际应从分片文件合并数据
            out.write("ML_MODEL_DATA".getBytes());
        }
        
        return targetPath.toString();
    }
}

package com.example.mlplatform.util;

import java.nio.file.*;
import java.util.*;

public class PathUtil {
    // 规范化路径格式
    public static String normalizePath(String inputPath) {
        // 处理Windows路径格式
        String unixPath = inputPath.replace("\\\\\\\\", "/");
        
        // 分割路径组件
        List<String> pathComponents = new ArrayList<>(Arrays.asList(unixPath.split("/")));
        
        // 移除空组件
        pathComponents.removeAll(Collections.singletonList(""));
        
        return String.join(File.separator, pathComponents);
    }
}