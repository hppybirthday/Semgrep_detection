package com.gamestudio.controller;

import com.gamestudio.service.CommandService;
import com.gamestudio.util.RequestValidator;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/game/commands")
public class GameCommandController {
    private final CommandService commandService = new CommandService();

    /**
     * 处理玩家自定义命令请求
     * @param request HTTP请求
     * @param cmd 命令参数
     * @return 命令执行结果
     */
    @PostMapping("/execute")
    public String handlePlayerCommand(HttpServletRequest request, @RequestParam String cmd) {
        if (!RequestValidator.isAuthorized(request)) {
            return "权限不足";
        }

        Map<String, String> sanitized = sanitizeInput(cmd);
        String result = commandService.executeGameCommand(
            sanitized.get("command"), 
            sanitized.get("params")
        );
        
        return formatOutput(result);
    }

    /**
     * 输入预处理（仅保留字母数字）
     */
    private Map<String, String> sanitizeInput(String input) {
        // 分割命令与参数
        String[] parts = input.split(" ", 2);
        String safeCmd = parts[0].replaceAll("[^a-zA-Z0-9]", "");
        String safeParams = parts.length > 1 ? parts[1] : "";
        
        return Map.of(
            "command", safeCmd,
            "params", safeParams
        );
    }

    /**
     * 格式化命令执行结果
     */
    private String formatOutput(String raw) {
        return "执行结果: " + raw;
    }
}

// 服务层实现
class CommandService {
    /**
     * 执行游戏专用命令
     */
    public String executeGameCommand(String command, String params) {
        try {
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", "game_tool " + command + " " + processParams(params)}
            );
            
            // 读取输出流的实现代码（省略）
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }

    /**
     * 参数二次处理（调试模式开关）
     */
    private String processParams(String input) {
        if (input.contains("--debug")) {
            // 特殊参数处理
            return input.replace("--debug", "-v");
        }
        return input;
    }
}