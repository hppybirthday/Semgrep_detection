package com.gamestudio.xss;

import java.util.ArrayList;
import java.util.List;

// 领域模型：玩家实体
class Player {
    private String name;
    private int score;

    public Player(String name) {
        this.name = name;
        this.score = 0;
    }

    public String getName() { return name; }
    public int getScore() { return score; }
    public void addScore(int points) { this.score += points; }
}

// 领域服务：游戏管理
class GameService {
    private List<Player> players = new ArrayList<>();

    // 注册新玩家（存在XSS漏洞）
    public void registerPlayer(String rawName) {
        // 直接使用用户输入构造玩家对象
        players.add(new Player(rawName));
    }

    // 生成玩家排行榜HTML（漏洞触发点）
    public String generateLeaderboardHTML() {
        StringBuilder html = new StringBuilder();
        html.append("<div class='leaderboard'><h2>排行榜</h2><ul>");
        
        // 将玩家名称直接拼接到HTML中，未进行任何转义处理
        for (Player player : players) {
            html.append(String.format(
                "<li>%s - %d 分</li>",
                player.getName(),  // 这里直接使用原始用户输入
                player.getScore()
            ));
        }
        
        html.append("</ul></div>");
        return html.toString();
    }
}

// 应用层：游戏主类
public class GameApplication {
    public static void main(String[] args) {
        GameService game = new GameService();
        
        // 模拟用户注册（包含恶意输入）
        game.registerPlayer("<script>alert('XSS攻击成功！')</script>");
        game.registerPlayer("正常玩家");
        
        // 生成包含恶意内容的HTML
        System.out.println("生成的排行榜HTML：");
        System.out.println(game.generateLeaderboardHTML());
    }
}
