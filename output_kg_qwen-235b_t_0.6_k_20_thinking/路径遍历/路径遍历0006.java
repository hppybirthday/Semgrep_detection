package com.gamestudio.core.domain;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 游戏资源加载器（存在路径遍历漏洞）
 * 用于演示桌面游戏中的资源加载漏洞
 */
public class ResourceLoader {
    private final String baseResourcePath;

    public ResourceLoader(String baseResourcePath) {
        this.baseResourcePath = baseResourcePath;
    }

    /**
     * 加载游戏资源文件（存在安全漏洞）
     * @param resourceName 用户指定的资源名称
     * @return 文件内容
     * @throws IOException 如果文件读取失败
     */
    public String loadResource(String resourceName) throws IOException {
        // 漏洞点：直接拼接用户输入
        File resourceFile = new File(baseResourcePath, resourceName);
        
        // 模拟加载资源文件
        if (!resourceFile.exists()) {
            throw new IOException("Resource not found: " + resourceName);
        }
        
        return new String(Files.readAllBytes(resourceFile.toPath()));
    }
}

// 游戏核心领域类
package com.gamestudio.core.domain;

import java.io.IOException;

public class GameResourceService {
    private final ResourceLoader resourceLoader;

    public GameResourceService(String baseResourcePath) {
        this.resourceLoader = new ResourceLoader(baseResourcePath);
    }

    /**
     * 处理玩家自定义资源请求
     * @param resourceName 用户提供的资源名称
     * @return 处理结果
     */
    public String handlePlayerResourceRequest(String resourceName) {
        try {
            // 直接使用用户输入加载资源
            return resourceLoader.loadResource(resourceName);
        } catch (IOException e) {
            return "Error loading resource: " + e.getMessage();
        }
    }
}

// 应用服务层
package com.gamestudio.applicationservice;

import com.gamestudio.core.domain.GameResourceService;

public class ResourceApplicationService {
    private final GameResourceService gameResourceService;

    public ResourceApplicationService(String baseResourcePath) {
        this.gameResourceService = new GameResourceService(baseResourcePath);
    }

    /**
     * 处理资源请求
     * @param playerName 玩家名称
     * @param resourceName 资源名称
     * @return 响应内容
     */
    public String processResourceRequest(String playerName, String resourceName) {
        // 记录玩家请求日志
        System.out.println("Player " + playerName + " requested resource: " + resourceName);
        
        // 处理资源请求（存在漏洞）
        return gameResourceService.handlePlayerResourceRequest(resourceName);
    }
}

// 主程序入口
package com.gamestudio;

import com.gamestudio.applicationservice.ResourceApplicationService;

public class GameLauncher {
    public static void main(String[] args) {
        // 初始化资源服务（配置错误的基础路径）
        ResourceApplicationService service = new ResourceApplicationService("./resources/");
        
        // 模拟玩家请求（正常用法）
        System.out.println("Normal request:");
        System.out.println(service.processResourceRequest("Player1", "textures/character1.png"));
        
        // 模拟攻击向量（路径遍历攻击）
        System.out.println("\
Path traversal attack:");
        System.out.println(service.processResourceRequest("Hacker", "../../test.txt"));
    }
}