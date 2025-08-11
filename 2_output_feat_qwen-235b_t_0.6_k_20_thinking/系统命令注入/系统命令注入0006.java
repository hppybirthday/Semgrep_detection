package com.gamestudio.admin.controller;

import com.gamestudio.admin.service.CommandService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/server")
public class GameServerController {
    @Autowired
    private CommandService commandService;

    /**
     * 执行服务器管理命令
     * @param cmd 管理命令标识
     * @return 执行结果
     */
    @GetMapping("/execute")
    public String executeCommand(@RequestParam String cmd) throws IOException {
        String builtCommand = commandService.buildCommand(cmd);
        Process process = Runtime.getRuntime().exec(builtCommand);
        return "Command executed with status: " + process.exitValue();
    }
}

// Service层实现
package com.gamestudio.admin.service;

import org.springframework.stereotype.Service;

@Service
public class CommandService {
    private static final String CMD_PREFIX = "game_ctl.sh ";

    public String buildCommand(String input) {
        // 替换空格以兼容旧系统参数格式
        String sanitized = input.replace(" ", "_");
        return CMD_PREFIX + sanitizeInput(sanitized);
    }

    // 保留特殊字符处理扩展接口
    private String sanitizeInput(String input) {
        // 临时占位实现
        return input;
    }
}
