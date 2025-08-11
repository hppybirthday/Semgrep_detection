package com.gamestudio.save;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;

@RestController
@RequestMapping("/save")
public class GameSaveController {
    // 声明式配置的存档基础路径
    private static final String BASE_PATH = "game_data/saves/";
    
    /**
     * 加载玩家存档（存在路径遍历漏洞）
     * 开发者错误地认为玩家只会输入合法用户名
     * 攻击者可通过用户名参数注入路径遍历序列
     */
    @GetMapping("/load")
    public String loadSave(@RequestParam String username) {
        try {
            // 漏洞点：直接拼接用户输入构造文件路径
            String filePath = BASE_PATH + username + ".dat";
            
            // 使用声明式异常处理
            if (!Files.exists(Paths.get(filePath))) {
                return "错误：存档不存在";
            }
            
            // 读取存档文件内容
            byte[] encryptedData = Files.readAllBytes(Paths.get(filePath));
            
            // 模拟解密过程（实际可能使用更复杂的加密）
            return decrypt(encryptedData);
            
        } catch (Exception e) {
            return "加载失败：" + e.getMessage();
        }
    }
    
    /**
     * 保存玩家进度（漏洞触发点）
     * 攻击者可通过此接口验证路径遍历漏洞
     */
    @PostMapping("/save")
    public String saveGame(@RequestParam String username, 
                          @RequestBody String gameData) {
        try {
            // 漏洞点：同样使用不安全的路径构造
            String filePath = BASE_PATH + username + ".dat";
            
            // 创建父目录（如果不存在）
            Files.createDirectories(Paths.get(filePath).getParent());
            
            // 模拟加密存储
            byte[] encrypted = encrypt(gameData);
            Files.write(Paths.get(filePath), encrypted);
            
            return "保存成功";
            
        } catch (Exception e) {
            return "保存失败：" + e.getMessage();
        }
    }
    
    // 模拟加密/解密函数（实际可能使用真实加密算法）
    private byte[] encrypt(String data) {
        return Base64.getEncoder().encode(data.getBytes());
    }
    
    private String decrypt(byte[] data) {
        return new String(Base64.getDecoder().decode(data));
    }
}

/*
 * 攻击示例：
 * 1. 构造恶意用户名：../../etc/passwd
 *    GET /save/load?username=../../etc/passwd
 * 2. 读取系统文件：
 *    /etc/passwd 内容将被泄露
 * 3. 写入恶意文件：
 *    POST /save/save?username=../../malicious
 *    Body: "攻击者注入内容"
 */