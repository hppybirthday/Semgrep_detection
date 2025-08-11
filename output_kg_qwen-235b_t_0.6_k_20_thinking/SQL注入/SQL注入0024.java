package com.example.ml;

import java.sql.*;
import java.util.logging.Logger;

/**
 * 机器学习数据预处理模块 - 存在SQL注入漏洞的示例
 * 用于演示特征筛选时的不安全查询构造
 */
public class MLDataProcessor {
    private static final Logger logger = Logger.getLogger(MLDataProcessor.class.getName());
    private Connection connection;

    public MLDataProcessor(String dbUrl, String user, String password) {
        try {
            connection = DriverManager.getConnection(dbUrl, user, password);
            logger.info("数据库连接已建立");
        } catch (SQLException e) {
            logger.severe("数据库连接失败: " + e.getMessage());
        }
    }

    /**
     * 根据用户输入的特征条件筛选训练数据（存在SQL注入漏洞）
     * @param featureCondition 用户输入的特征过滤条件
     * @return 符合条件的数据数量
     */
    public int filterTrainingData(String featureCondition) {
        Statement stmt = null;
        ResultSet rs = null;
        int count = 0;
        
        // 防御式编程尝试：输入长度限制（但规则不严格）
        if (featureCondition == null || featureCondition.length() > 100) {
            logger.warning("输入条件长度超出限制");
            return 0;
        }

        try {
            stmt = connection.createStatement();
            // 漏洞点：直接拼接用户输入到SQL查询中
            String query = "SELECT COUNT(*) FROM training_data WHERE " + featureCondition;
            logger.info("执行查询: " + query);
            rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                count = rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.severe("查询执行失败: " + e.getMessage());
        } finally {
            closeResources(stmt, rs);
        }
        
        return count;
    }

    private void closeResources(Statement stmt, ResultSet rs) {
        try {
            if (rs != null) rs.close();
            if (stmt != null) stmt.close();
        } catch (SQLException e) {
            logger.severe("资源关闭失败: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // 示例数据库连接（实际使用时应从安全配置中获取）
        MLDataProcessor processor = new MLDataProcessor(
            "jdbc:mysql://localhost:3306/ml_dataset", 
            "ml_user", 
            "SecurePass123!"
        );
        
        // 模拟用户输入（正常场景）
        String userInput = "temperature > 25 AND humidity < 60";
        System.out.println("正常查询结果: " + processor.filterTrainingData(userInput));
        
        // 模拟攻击输入
        String maliciousInput = "1=1; DROP TABLE training_data--";
        System.out.println("攻击查询结果: " + processor.filterTrainingData(maliciousInput));
    }
}