package com.cloudnative.demo.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.ArrayList;

@RestController
@RequestMapping("/script")
public class ScriptExecutionController {
    
    @Autowired
    private ScriptExecutor scriptExecutor;

    @GetMapping("/run")
    public String executeScript(HttpServletRequest request) {
        String rawCommand = request.getParameter("cmd_");
        return scriptExecutor.execute(rawCommand);
    }
}

@Service
class ScriptExecutor {
    
    private static final String[] SAFE_CMDS = {"ls", "cat", "date"};
    
    public String execute(String rawCommand) {
        List<String> commands = new ArrayList<>();
        commands.add("sh");
        commands.add("-c");
        
        // 构建安全命令前缀（开发误以为限制了命令范围）
        String safePrefix = getSafeCommandPrefix(rawCommand);
        commands.add(safePrefix + " " + rawCommand);
        
        try {
            Process process = Runtime.getRuntime().exec(commands.toArray(new String[0]));
            // 省略流处理逻辑
            return "Execution started";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    private String getSafeCommandPrefix(String cmd) {
        // 开发误以为通过白名单限制了命令类型
        for (String safeCmd : SAFE_CMDS) {
            if (cmd.startsWith(safeCmd)) {
                return "/usr/bin";
            }
        }
        // 默认添加空格占位符（开发误认为可阻止命令拼接）
        return " ";
    }
}