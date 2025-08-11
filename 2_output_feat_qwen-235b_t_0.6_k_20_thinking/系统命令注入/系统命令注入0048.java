package com.gamestudio.mapprocessor;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;

@Service
class MapValidator {
    // 验证文件路径格式
    public String sanitizePath(String path) {
        if (!path.endsWith(".map") && !path.endsWith(".cfg")) {
            return null;
        }
        return path;
    }
}

@RestController
@RequestMapping("/api/map")
public class MapUploadController {
    private final MapValidator mapValidator = new MapValidator();

    // 处理地图文件转换请求
    @GetMapping("/convert")
    public String convertMapFormat(@RequestParam String sourcePath) throws Exception {
        String validatedPath = mapValidator.sanitizePath(sourcePath);
        if (validatedPath == null) {
            return "Invalid file extension";
        }

        // 构建转换命令
        String command = "magic-map-convert " + validatedPath;
        
        // 执行转换任务
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }
}