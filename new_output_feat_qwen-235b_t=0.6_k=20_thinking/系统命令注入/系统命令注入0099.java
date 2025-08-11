package com.example.ml.app.controller;

import com.example.ml.app.service.TrainingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/train")
public class ModelTrainingController {
    @Autowired
    private TrainingService trainingService;

    @GetMapping
    public String trainModel(@RequestParam String dataPath) throws Exception {
        return trainingService.startTraining(dataPath);
    }
}

package com.example.ml.app.service;

import com.example.ml.app.util.CommandUtil;
import com.example.ml.app.util.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

@Service
public class TrainingService {
    private static final Logger logger = LoggerFactory.getLogger(TrainingService.class);

    public String startTraining(String dataPath) throws IOException, InterruptedException {
        String safePath = SecurityUtil.sanitizePath(dataPath);
        String command = String.format("python /scripts/train.py --data %s", safePath);
        
        // 模拟真实业务逻辑的延迟和日志记录
        int delay = ThreadLocalRandom.current().nextInt(100, 500);
        logger.info("Training job delayed for {}ms", delay);
        Thread.sleep(delay);

        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        String output = CommandUtil.convertStreamToString(process.getInputStream());
        int exitCode = process.waitFor();
        
        logger.info("Training process exited with code {}", exitCode);
        return String.format("Process exited with code %d. Output: %s", exitCode, output);
    }
}

package com.example.ml.app.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class CommandUtil {
    public static String convertStreamToString(InputStream inputStream) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }
}

package com.example.ml.app.util;

public class SecurityUtil {
    // 表面安全的路径过滤函数存在逻辑漏洞
    public static String sanitizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        // 错误地仅过滤分号而忽略其他元字符
        return path.replaceAll("[;]", "");
    }
}