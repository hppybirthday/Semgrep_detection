package com.bank.security;

import java.sql.*;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * 银行账户查询服务
 * 采用高抽象建模风格实现账户余额查询功能
 * 存在SQL注入漏洞的示例代码
 */
public class AccountService {
    private Connection connection;
    private Logger logger = Logger.getLogger(AccountService.class.getName());

    public AccountService() {
        try {
            // 初始化数据库连接（简化版配置）
            Properties props = new Properties();
            props.setProperty("user", "bank_user");
            props.setProperty("password", "secure_pass");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/bank_db", props);
        } catch (SQLException e) {
            logger.severe("数据库连接初始化失败: " + e.getMessage());
        }
    }

    /**
     * 查询账户余额（存在SQL注入漏洞）
     * @param accountId 用户输入的账户ID
     * @return 账户余额
     */
    public double checkBalance(String accountId) {
        double balance = 0.0;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // 漏洞点：直接拼接SQL语句
            String query = "SELECT balance FROM accounts WHERE account_id = '" 
                          + accountId + "'";
            
            stmt = connection.createStatement();
            rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                balance = rs.getDouble("balance");
            }
            
        } catch (SQLException e) {
            logger.warning("查询失败: " + e.getMessage() + ", SQL: " + accountId);
        } finally {
            closeResources(stmt, rs);
        }
        
        return balance;
    }

    /**
     * 转账功能（使用安全方式实现）
     * @param fromAccount 源账户
     * @param toAccount 目标账户
     * @param amount 金额
     * @return 是否成功
     */
    public boolean transfer(String fromAccount, String toAccount, double amount) {
        // 安全实现：使用PreparedStatement
        String sql = "UPDATE accounts SET balance = balance - ? WHERE account_id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setDouble(1, amount);
            pstmt.setString(2, fromAccount);
            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            logger.severe("转账失败: " + e.getMessage());
            return false;
        }
    }

    private void closeResources(Statement stmt, ResultSet rs) {
        try {
            if (rs != null) rs.close();
            if (stmt != null) stmt.close();
        } catch (SQLException e) {
            logger.warning("资源关闭失败: " + e.getMessage());
        }
    }

    // 模拟Controller层
    public static void main(String[] args) {
        AccountService service = new AccountService();
        
        // 正常使用示例
        System.out.println("正常账户余额: " + service.checkBalance("12345"));
        
        // 恶意输入示例（SQL注入攻击）
        String maliciousInput = "' OR '1'='1";
        System.out.println("注入攻击结果: " + service.checkBalance(maliciousInput));
    }
}