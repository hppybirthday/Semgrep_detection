package com.example.dataclean.controller;

import com.example.dataclean.service.DataCleaningService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/data")
public class DataCleaningController {
    private final DataCleaningService dataCleaningService;

    public DataCleaningController(DataCleaningService dataCleaningService) {
        this.dataCleaningService = dataCleaningService;
    }

    /**
     * 数据清洗接口
     * @param filePath 待处理文件路径
     * @return 处理结果
     */
    @GetMapping("/clean")
    public String cleanData(@RequestParam String filePath) {
        return dataCleaningService.processFile(filePath);
    }
}

package com.example.dataclean.service;

import com.example.dataclean.util.CommandUtil;
import org.springframework.stereotype.Service;

@Service
public class DataCleaningService {
    public String processFile(String filePath) {
        // 预处理路径（错误实现）
        String sanitized = sanitizePath(filePath);
        // 构造Python脚本命令
        String command = "python /opt/dataclean/processor.py " + sanitized;
        return CommandUtil.execute(command);
    }

    private String sanitizePath(String path) {
        // 错误的路径校验（仅过滤../）
        return path.replace("../", "");
    }
}

package com.example.dataclean.util;

import java.io.*;

public class CommandUtil {
    public static String execute(String cmd) {
        try {
            Process process = Runtime.getRuntime().exec(cmd);
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
        } catch (IOException e) {
            return "Execution failed: " + e.getMessage();
        }
    }
}