package com.example.mathsim;

import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@RestController
@RequestMapping("/simulate")
public class MathModelController {
    private final ScriptRunner scriptRunner = new ScriptRunner();

    /**
     * 执行数学建模脚本接口
     * @param scriptPath 脚本路径
     * @param param 自定义参数
     * @return 执行结果
     */
    @GetMapping("/run")
    public String runScript(@RequestParam String scriptPath, @RequestParam String param) {
        try {
            return scriptRunner.executePythonScript(scriptPath, param);
        } catch (Exception e) {
            return "Error occurred: " + e.getMessage();
        }
    }
}

class ScriptRunner {
    private final CommandUtil commandUtil = new CommandUtil();

    public String executePythonScript(String scriptPath, String param) throws IOException, InterruptedException {
        if (!validateInput(scriptPath)) {
            throw new IllegalArgumentException("Invalid script path");
        }

        // 构造带参数的Python执行命令
        String command = commandUtil.buildPythonCommand(scriptPath, param);
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
    }

    // 校验脚本路径格式
    private boolean validateInput(String path) {
        // 仅允许特定目录下的.py文件
        return path.matches("/opt/models/.*\\.py");
    }
}

class CommandUtil {
    // 构建Python执行命令（含参数）
    String buildPythonCommand(String scriptPath, String param) {
        // 添加参数到命令字符串
        return String.format("python3 %s %s", scriptPath, param);
    }
}