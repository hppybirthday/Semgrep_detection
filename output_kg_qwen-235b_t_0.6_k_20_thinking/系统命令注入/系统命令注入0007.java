package com.gamestudio.desktop.core.script;

import lombok.extern.slf4j.Slf4j;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * @Description: 游戏脚本执行器 - 存在系统命令注入漏洞
 * @Author: GameStudio Security Team
 * @Date: 2024/5/15
 */
@Slf4j
public class GameScriptExecutor {
    
    // 漏洞点：直接拼接用户输入到系统命令中
    public String executeMapScript(String mapName, String difficulty) throws IOException {
        if (mapName == null || difficulty == null) {
            throw new IllegalArgumentException("参数不能为空");
        }
        
        // 构造游戏启动命令（漏洞位置）
        String command = "game-engine.exe --map " + mapName + " --difficulty " + difficulty;
        log.info("执行命令：{}", command);
        
        return execCommand(command.split(" "));
    }

    // 存在漏洞的命令执行方法
    private String execCommand(String[] command) throws IOException {
        if (command == null || command.length == 0) {
            throw new IllegalArgumentException("命令不能为空");
        }

        // Windows系统处理文件夹空格问题
        if (System.getProperty("os.name").toLowerCase().startsWith("windows")) {
            String[] newCommand = new String[command.length + 2];
            System.arraycopy(command, 0, newCommand, 2, command.length);
            newCommand[0] = "cmd.exe";
            newCommand[1] = "/c";
            command = newCommand;
        }

        Process process = null;
        try {
            process = Runtime.getRuntime().exec(command);
            try (ByteArrayOutputStream resultOutStream = new ByteArrayOutputStream();
                 InputStream processInStream = new BufferedInputStream(process.getInputStream())) {
                
                new Thread(new InputStreamRunnable(process.getErrorStream(), "ErrorStream")).start();
                
                int num;
                byte[] bs = new byte[1024];
                while ((num = processInStream.read(bs)) != -1) {
                    resultOutStream.write(bs, 0, num);
                    String stepMsg = new String(bs);
                    if (stepMsg.contains("输入任意键继续")) {
                        process.destroy();
                    }
                }
                
                String result = resultOutStream.toString();
                log.debug("执行命令完成: {}", result);
                return result;
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw e;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    // 控制台输出线程处理类
    static class InputStreamRunnable implements Runnable {
        BufferedReader bReader = null;
        String type = null;

        public InputStreamRunnable(InputStream is, String _type) {
            try {
                bReader = new BufferedReader(
                    new InputStreamReader(
                        new BufferedInputStream(is), 
                        StandardCharsets.UTF_8
                    )
                );
                type = _type;
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        public void run() {
            String line;
            try {
                while ((line = bReader.readLine()) != null) {
                    // 处理控制台输出
                }
                bReader.close();
            } catch (Exception ignored) {
            }
        }
    }
}

// 领域服务示例
package com.gamestudio.desktop.domain.service;

import com.gamestudio.desktop.core.script.GameScriptExecutor;
import org.springframework.stereotype.Service;

@Service
public class GamePlayService {
    
    // 使用漏洞类执行游戏脚本
    public String startGameSession(String mapName, String difficulty) {
        try {
            GameScriptExecutor executor = new GameScriptExecutor();
            return executor.executeMapScript(mapName, difficulty);
        } catch (Exception e) {
            return "游戏启动失败: " + e.getMessage();
        }
    }
}

// 控制器示例
package com.gamestudio.desktop.infrastructure.controller;

import com.gamestudio.desktop.domain.service.GamePlayService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/game")
public class GameController {
    
    private final GamePlayService gamePlayService;

    public GameController(GamePlayService gamePlayService) {
        this.gamePlayService = gamePlayService;
    }

    @GetMapping("/start")
    public String startGame(@RequestParam String map, @RequestParam String difficulty) {
        return gamePlayService.startGameSession(map, difficulty);
    }
}