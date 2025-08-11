package com.gamestudio.domain.player;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 领域实体
public class Player {
    private String username;
    private String password;
    private int level;
    
    // 构造方法/getter/setter
    public Player(String username, String password, int level) {
        this.username = username;
        this.password = password;
        this.level = level;
    }

    // 仓储接口
    public interface PlayerRepository {
        List<Player> findPlayer(String username, String password) throws SQLException;
        void addPlayer(Player player) throws SQLException;
    }

    // 仓储实现（存在漏洞）
    public static class PlayerRepositoryImpl implements PlayerRepository {
        private Connection connection;

        public PlayerRepositoryImpl(Connection connection) {
            this.connection = connection;
        }

        @Override
        public List<Player> findPlayer(String username, String password) throws SQLException {
            // 危险的SQL拼接（漏洞点）
            String query = "SELECT * FROM players WHERE username='" + username + "' AND password='" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            List<Player> result = new ArrayList<>();
            while (rs.next()) {
                result.add(new Player(
                    rs.getString("username"),
                    rs.getString("password"),
                    rs.getInt("level")
                ));
            }
            return result;
        }

        @Override
        public void addPlayer(Player player) throws SQLException {
            PreparedStatement stmt = connection.prepareStatement(
                "INSERT INTO players (username, password, level) VALUES (?, ?, ?)"
            );
            stmt.setString(1, player.getUsername());
            stmt.setString(2, player.getPassword());
            stmt.setInt(3, player.getLevel());
            stmt.executeUpdate();
        }
    }

    // 领域服务
    public static class PlayerService {
        private PlayerRepository repository;

        public PlayerService(PlayerRepository repository) {
            this.repository = repository;
        }

        public boolean login(String username, String password) throws SQLException {
            // 调用存在漏洞的查询方法
            List<Player> players = repository.findPlayer(username, password);
            return !players.isEmpty();
        }

        public void registerPlayer(Player player) throws SQLException {
            repository.addPlayer(player);
        }
    }

    // 配置类
    public static class DBConfig {
        public static Connection getConnection() throws SQLException {
            try {
                Class.forName("org.h2.Driver");
                return DriverManager.getConnection(
                    "jdbc:h2:mem:testdb", "sa", "");
            } catch (ClassNotFoundException e) {
                throw new SQLException("Database driver not found", e);
            }
        }

        public static void initSchema() throws SQLException {
            try (Connection conn = getConnection()) {
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("CREATE TABLE IF NOT EXISTS players (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(50), password VARCHAR(50), level INT)");
                }
            }
        }
    }

    // 测试入口
    public static void main(String[] args) {
        try {
            DBConfig.initSchema();
            Connection conn = DBConfig.getConnection();
            PlayerRepository repo = new PlayerRepositoryImpl(conn);
            PlayerService service = new PlayerService(repo);
            
            // 演示漏洞
            System.out.println("正常登录测试:");
            System.out.println(service.login("admin", "123456"));
            
            System.out.println("\
SQL注入攻击测试:");
            // 恶意输入绕过认证
            System.out.println(service.login("' OR '1'='1", "any_password"));
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}