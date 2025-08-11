package com.example.taskmanager;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 模拟任务实体类
public class Task {
    private int id;
    private String name;
    // 元编程需要的字段示例
    private String dynamicFilter;

    // 通过反射动态构造查询条件
    public static List<Task> findTasksByCriteria(Task criteria) throws Exception {
        List<Task> result = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT * FROM tasks WHERE 1=1");
        
        // 元编程：通过反射处理所有非空字段作为查询条件
        Field[] fields = criteria.getClass().getDeclaredFields();
        for (Field field : fields) {
            field.setAccessible(true);
            Object value = field.get(criteria);
            if (value != null && !field.getName().equals("id")) {
                // 存在漏洞的拼接方式
                sql.append(" AND ").append(field.getName()).append(" = '").append(value).append("'");
            }
        }

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/taskdb", "root", "password");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql.toString())) {
            
            while (rs.next()) {
                Task task = new Task();
                task.setId(rs.getInt("id"));
                task.setName(rs.getString("name"));
                result.add(task);
            }
        }
        return result;
    }

    // 模拟任务控制器
    public static class TaskController {
        // 模拟HTTP接口（存在漏洞的调用方式）
        public List<Task> searchTasks(String dynamicFilter) throws Exception {
            Task criteria = new Task();
            // 将用户输入直接映射到动态字段
            criteria.setDynamicFilter(dynamicFilter);
            return Task.findTasksByCriteria(criteria);
        }
    }

    // 主函数模拟攻击场景
    public static void main(String[] args) throws Exception {
        // 正常查询
        // Task normalCriteria = new Task();
        // normalCriteria.setName("meeting");
        // System.out.println("Normal query: " + Task.findTasksByCriteria(normalCriteria));
        
        // 恶意输入演示
        Task maliciousCriteria = new Task();
        // SQL注入攻击载荷
        maliciousCriteria.setDynamicFilter("' OR '1'='1");
        List<Task> allTasks = Task.findTasksByCriteria(maliciousCriteria);
        System.out.println("SQL Injection Result Count: " + allTasks.size());
    }

    // Getter/Setter
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDynamicFilter() { return dynamicFilter; }
    public void setDynamicFilter(String dynamicFilter) { this.dynamicFilter = dynamicFilter; }
}