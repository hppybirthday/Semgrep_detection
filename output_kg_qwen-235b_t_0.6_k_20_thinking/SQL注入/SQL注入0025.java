package com.example.bigdata.service;

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * 使用元编程实现的大数据查询服务（存在SQL注入漏洞）
 */
public abstract class AbstractBigDataService<T> {
    
    private Class<T> modelClass;
    private String tableName;
    
    public AbstractBigDataService() {
        try {
            // 通过反射获取泛型类型
            ParameterizedType pt = (ParameterizedType) this.getClass().getGenericSuperclass();
            modelClass = (Class<T>) pt.getActualTypeArguments()[0];
            
            // 假设通过注解获取表名（简化处理）
            tableName = modelClass.getSimpleName().toLowerCase() + "s";
            
        } catch (Exception e) {
            throw new RuntimeException("初始化失败: " + e.getMessage());
        }
    }
    
    // 模拟元编程方式的动态查询
    public List<T> queryWithDynamicFilter(String filterField, String filterValue) {
        List<T> results = new ArrayList<>();
        Connection conn = null;
        
        try {
            // 模拟连接数据库
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/bigdata_db", "user", "pass");
            
            // 漏洞点：直接拼接SQL（元编程动态构建查询）
            String sql = "SELECT * FROM " + tableName + 
                        " WHERE " + filterField + " = '" + filterValue + "'";
            
            System.out.println("执行SQL: " + sql); // 模拟日志输出
            
            // 使用普通Statement（错误实践）
            java.sql.Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            
            // 模拟结果转换（简化处理）
            while (rs.next()) {
                T instance = modelClass.newInstance();
                
                // 模拟反射填充数据（简化）
                Field[] fields = modelClass.getDeclaredFields();
                for (Field field : fields) {
                    field.setAccessible(true);
                    // 实际应根据字段类型处理
                    field.set(instance, rs.getObject(field.getName()));
                }
                
                results.add(instance);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 关闭连接（简化）
            if (conn != null) {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
        
        return results;
    }
    
    // 模拟大数据分析的复杂查询
    public List<T> complexAnalysisQuery(String groupByField, String havingCondition) {
        List<T> results = new ArrayList<>();
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/bigdata_db", "user", "pass");
            
            // 严重漏洞：直接拼接分组和HAVING条件
            String sql = "SELECT " + groupByField + ", COUNT(*) as count " +
                        "FROM " + tableName + 
                        " GROUP BY " + groupByField +
                        " HAVING " + havingCondition;
            
            System.out.println("执行复杂查询: " + sql);
            
            java.sql.Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            // ...结果处理逻辑（简化）
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (conn != null) {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
        
        return results;
    }
    
    // 模拟动态排序（存在注入点）
    public List<T> dynamicSort(String sortField, String sortOrder) {
        List<T> results = new ArrayList<>();
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/bigdata_db", "user", "pass");
            
            // 危险的排序字段拼接
            String sql = "SELECT * FROM " + tableName +
                        " ORDER BY " + sortField + " " + sortOrder;
            
            System.out.println("执行排序查询: " + sql);
            
            java.sql.Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            // ...结果处理（简化）
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (conn != null) {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
        
        return results;
    }
    
    // 模拟动态列选择（存在注入）
    public List<T> selectSpecificColumns(String columns, String whereClause) {
        List<T> results = new ArrayList<>();
        Connection conn = null;
        
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/bigdata_db", "user", "pass");
            
            // 高风险拼接
            String sql = "SELECT " + columns + " FROM " + tableName +
                        " WHERE " + whereClause;
            
            System.out.println("执行列选择查询: " + sql);
            
            java.sql.Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            // ...结果处理（简化）
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (conn != null) {
                try { conn.close(); } catch (Exception ignored) {}
            }
        }
        
        return results;
    }
}