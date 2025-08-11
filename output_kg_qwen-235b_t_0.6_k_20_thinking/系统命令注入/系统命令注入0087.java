package com.example.gamedemo.domain;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * @Description: 玩家设置聚合根
 * @Author: security-expert
 */
public class PlayerSettings {
    private String playerName;
    private String gameDirectory;

    public PlayerSettings(String playerName, String gameDirectory) {
        this.playerName = playerName;
        this.gameDirectory = gameDirectory;
    }

    public String getPlayerName() {
        return playerName;
    }

    public String getGameDirectory() {
        return gameDirectory;
    }

    public void validateGameDirectory() throws IOException {
        // 模拟检查游戏目录是否存在（存在漏洞的实现）
        Process process = Runtime.getRuntime().exec("ls -la " + gameDirectory);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
        int exitCode = process.exitValue();
        System.out.println("验证完成，退出码：" + exitCode);
    }
}

package com.example.gamedemo.application;

import com.example.gamedemo.domain.PlayerSettings;
import com.example.gamedemo.infrastructure.SettingsRepository;

/**
 * @Description: 玩家设置应用服务
 * @Author: security-expert
 */
public class PlayerSettingsService {
    private SettingsRepository repository;

    public PlayerSettingsService(SettingsRepository repository) {
        this.repository = repository;
    }

    public void saveSettings(String playerName, String gameDirectory) {
        PlayerSettings settings = new PlayerSettings(playerName, gameDirectory);
        repository.save(settings);
    }

    public void validateAndSaveSettings(String playerName, String gameDirectory) throws IOException {
        PlayerSettings settings = new PlayerSettings(playerName, gameDirectory);
        settings.validateGameDirectory();  // 存在漏洞的验证方法
        repository.save(settings);
    }
}

package com.example.gamedemo.infrastructure;

import com.example.gamedemo.domain.PlayerSettings;

/**
 * @Description: 持久化仓储接口
 * @Author: security-expert
 */
public interface SettingsRepository {
    void save(PlayerSettings settings);
}

package com.example.gamedemo.infrastructure.file;

import com.example.gamedemo.domain.PlayerSettings;
import java.io.*;

/**
 * @Description: 文件系统持久化实现
 * @Author: security-expert
 */
public class FileSettingsRepository implements SettingsRepository {
    private String storagePath;

    public FileSettingsRepository(String storagePath) {
        this.storagePath = storagePath;
    }

    @Override
    public void save(PlayerSettings settings) {
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(storagePath + "/" + settings.getPlayerName() + ".dat"))) {
            out.writeObject(settings);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

package com.example.gamedemo;

import com.example.gamedemo.application.PlayerSettingsService;
import com.example.gamedemo.infrastructure.file.FileSettingsRepository;

import java.io.IOException;
import java.util.Scanner;

/**
 * @Description: 游戏启动入口
 * @Author: security-expert
 */
public class GameLauncher {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("欢迎来到游戏设置系统");
        System.out.print("请输入玩家名称：");
        String name = scanner.nextLine();
        
        System.out.print("请输入游戏目录路径：");
        String path = scanner.nextLine();
        
        PlayerSettingsService service = new PlayerSettingsService(
            new FileSettingsRepository("./settings_data")
        );
        
        try {
            service.validateAndSaveSettings(name, path);
            System.out.println("设置保存成功！");
        } catch (IOException e) {
            System.err.println("设置保存失败：" + e.getMessage());
        }
    }
}