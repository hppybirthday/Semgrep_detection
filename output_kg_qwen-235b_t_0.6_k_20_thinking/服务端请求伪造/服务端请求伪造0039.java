package com.gamestudio.serverside;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// 高抽象建模：资源下载器接口
interface ResourceDownloader {
    String download(String urlString) throws IOException;
}

// 具体实现：HTTP资源下载器
class HttpResourceDownloader implements ResourceDownloader {
    @Override
    public String download(String urlString) throws IOException {
        StringBuilder content = new StringBuilder();
        URL url = new URL(urlString);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

// 游戏资源服务类
class GameAssetService {
    private final ResourceDownloader downloader;

    public GameAssetService(ResourceDownloader downloader) {
        this.downloader = downloader;
    }

    // 漏洞点：直接使用用户提供的URL
    public String downloadGameMap(String userProvidedUrl) throws IOException {
        return downloader.download(userProvidedUrl);
    }
}

// 游戏服务器模拟类
class GameServer {
    private final GameAssetService assetService;

    public GameServer() {
        this.assetService = new GameAssetService(new HttpResourceDownloader());
    }

    // 模拟处理客户端请求
    public String handleRequest(Map<String, String> params) {
        try {
            String mapUrl = params.get("mapUrl");
            // 危险操作：直接使用用户输入的URL
            return assetService.downloadGameMap(mapUrl);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        GameServer server = new GameServer();
        
        // 测试用例：正常情况
        System.out.println("--- 正常测试 ---");
        Map<String, String> normalParams = new HashMap<>();
        normalParams.put("mapUrl", "https://gamestudio.com/maps/forest.json");
        System.out.println(server.handleRequest(normalParams));
        
        // 测试用例：SSRF攻击（模拟攻击者请求）
        System.out.println("\
--- SSRF测试 ---");
        Map<String, String> attackParams = new HashMap<>();
        attackParams.put("mapUrl", "file:///etc/passwd"); // 本地文件读取
        System.out.println(server.handleRequest(attackParams));
        
        // 测试访问内部服务
        Map<String, String> internalParams = new HashMap<>();
        internalParams.put("mapUrl", "http://127.0.0.1:8080/admin/config");
        System.out.println(server.handleRequest(internalParams));
    }
}