package com.gamestudio.desktopgame.model;

import java.io.Serializable;

/**
 * 领域模型：游戏存档数据
 */
public class GameSave implements Serializable {
    private static final long serialVersionUID = 1L;
    private String playerName;
    private int levelProgress;
    private transient String secretData; // 敏感字段

    public GameSave(String playerName, int levelProgress) {
        this.playerName = playerName;
        this.levelProgress = levelProgress;
    }

    // 模拟敏感操作
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (secretData != null) {
            // 模拟执行敏感操作
            System.out.println("[敏感操作] 加载特殊存档: " + secretData);
        }
    }
}

package com.gamestudio.desktopgame.service;

import com.gamestudio.desktopgame.model.GameSave;
import java.io.*;

/**
 * 应用服务：游戏存档管理
 */
public class GameService {
    // 不安全的反序列化实现
    public GameSave loadGame(String filePath) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            // 危险：直接反序列化不可信数据
            return (GameSave) ois.readObject();
        }
    }

    public void saveGame(GameSave gameSave, String filePath) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(gameSave);
        }
    }
}

package com.gamestudio.desktopgame.application;

import com.gamestudio.desktopgame.model.GameSave;
import com.gamestudio.desktopgame.service.GameService;

import java.io.File;
import java.util.Scanner;

/**
 * 游戏主程序入口
 */
public class GameLauncher {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        GameService gameService = new GameService();

        System.out.println("==== 游戏存档加载器 ====");
        System.out.println("1. 创建新存档");
        System.out.println("2. 加载已有存档");
        System.out.print("请选择操作: ");

        int choice = Integer.parseInt(scanner.nextLine());

        try {
            if (choice == 1) {
                System.out.print("输入玩家名称: ");
                String name = scanner.nextLine();
                GameSave save = new GameSave(name, 1);
                gameService.saveGame(save, "game_save.dat");
                System.out.println("存档已创建");
            } else if (choice == 2) {
                System.out.print("输入存档文件路径: ");
                String path = scanner.nextLine();
                // 漏洞触发点：加载不受信任的存档文件
                GameSave loaded = gameService.loadGame(path);
                System.out.println("成功加载存档: " + loaded.getClass().getName());
            }
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}