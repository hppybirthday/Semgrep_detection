package com.bigdata.process;

import javax.websocket.OnMessage;
import javax.websocket.server.ServerEndpoint;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@ServerEndpoint("/data-task")
public class DataTaskHandler {
    
    @OnMessage
    public String handleTask(String jsonInput) {
        try {
            TaskParam param = ParamParser.parse(jsonInput);
            if (param == null) return "Invalid parameter";
            
            // 验证参数合法性
            if (!ParamValidator.validate(param)) {
                return "Validation failed";
            }
            
            // 构建数据处理命令
            String[] cmd = CommandBuilder.build(param);
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取处理结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            return result.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class ParamParser {
    // 模拟JSON参数解析
    static TaskParam parse(String jsonInput) {
        // 实际解析逻辑简化
        if (jsonInput == null || !jsonInput.contains("filepath")) return null;
        TaskParam param = new TaskParam();
        param.filepath = jsonInput.split("filepath":")[1]
            .split(",")[0].replace("\\"", "");
        return param;
    }
}

class ParamValidator {
    // 参数验证逻辑
    static boolean validate(TaskParam param) {
        // 简单白名单过滤
        if (param.filepath == null) return false;
        return param.filepath.matches("[a-zA-Z0-9_\\-\\/]+.csv");
    }
}

class CommandBuilder {
    // 构建系统命令
    static String[] build(TaskParam param) {
        // 数据处理脚本路径
        String scriptPath = "/opt/data/scripts/process.sh";
        return new String[]{"sh", "-c", scriptPath + " " + param.filepath};
    }
}

class TaskParam {
    String filepath;
}