package com.game.desktop.player;

import java.util.ArrayList;
import java.util.List;

// 领域实体
public class Player {
    private String id;
    private String name;
    private int score;

    public Player(String id, String name) {
        this.id = id;
        this.name = name;
        this.score = 0;
    }

    public String getName() { return name; }
    public int getScore() { return score; }
    public void addScore(int points) { this.score += points; }
}

// 应用服务
class PlayerService {
    private PlayerRepository repository = new PlayerRepository();

    public void registerPlayer(String id, String name) {
        Player player = new Player(id, name);
        repository.save(player);
    }

    public List<Player> getTopPlayers() {
        return repository.findTopPlayers();
    }
}

// 基础设施层
class PlayerRepository {
    private List<Player> players = new ArrayList<>();

    public void save(Player player) {
        players.add(player);
    }

    public List<Player> findTopPlayers() {
        return players.stream()
                .sorted((a, b) -> b.getScore() - a.getScore())
                .limit(10)
                .toList();
    }
}

// 漏洞展示类
public class LeaderboardRenderer {
    public static String renderLeaderboard(PlayerService service) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body><h1>Top Players</h1><ol>");
        
        // 漏洞点：直接拼接用户输入的name字段
        for (Player player : service.getTopPlayers()) {
            html.append("<li>")
                .append(player.getName())  // 未进行HTML转义
                .append(" - ")
                .append(player.getScore())
                .append("</li>");
        }
        
        html.append("</ol></body></html>");
        return html.toString();
    }

    // 模拟攻击示例
    public static void main(String[] args) {
        PlayerService service = new PlayerService();
        
        // 正常玩家注册
        service.registerPlayer("1", "Alice");
        service.registerPlayer("2", "Bob");
        
        // 恶意玩家注册（注入脚本）
        service.registerPlayer("3", "<script>alert('XSS漏洞触发！'+document.cookie)</script>");
        
        // 渲染排行榜时触发漏洞
        System.out.println(renderLeaderboard(service));
    }
}