package com.game.db;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 模拟桌面游戏玩家实体
public class Player {
    private int id;
    private String username;
    private int level;
    private int score;

    // 元编程核心类
    public static abstract class MetaDAO<T> {
        private final Connection conn;
        private final Class<T> type;

        public MetaDAO(Connection conn, Class<T> type) {
            this.conn = conn;
            this.type = type;
        }

        // 危险的反射查询方法
        public List<T> search(String field, String value) throws Exception {
            List<T> results = new ArrayList<>();
            String sql = "SELECT * FROM " + type.getSimpleName().toLowerCase() + "s WHERE " + field + "='" + value + "'";
            
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {

                while (rs.next()) {
                    T obj = type.getDeclaredConstructor().newInstance();
                    
                    for (Field f : type.getDeclaredFields()) {
                        f.setAccessible(true);
                        f.set(obj, rs.getObject(f.getName()));
                    }
                    results.add(obj);
                }
            }
            return results;
        }
    }

    // 游戏专用DAO
    public static class PlayerDAO extends MetaDAO<Player> {
        public PlayerDAO(Connection conn) {
            super(conn, Player.class);
        }
    }

    // 模拟游戏数据库操作
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/game_db", "root", "password")) {

            PlayerDAO dao = new PlayerDAO(conn);
            
            // 正常查询
            System.out.println("正常查询：");
            dao.search("username", "hero123").forEach(System.out::println);
            
            // SQL注入攻击演示
            System.out.println("\
注入攻击演示：");
            String payload = "x' OR '1'='1"; // 模拟攻击载荷
            dao.search("username", payload).forEach(System.out::println);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}