package com.bank.core.account;

import com.bank.core.common.Repository;
import com.bank.core.common.Service;
import com.bank.core.common.Controller;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 实体类
public class Account {
    private String accountId;
    private String ownerName;
    private double balance;
    
    // 构造方法/getter/setter
    public Account(String accountId, String ownerName, double balance) {
        this.accountId = accountId;
        this.ownerName = ownerName;
        this.balance = balance;
    }

    // Repository层
    public interface AccountRepository extends Repository<Account> {
        Account findAccountById(String accountId);
    }

    // 不安全的Repository实现
    public static class AccountRepositoryImpl implements AccountRepository {
        private Connection connection;

        public AccountRepositoryImpl(Connection connection) {
            this.connection = connection;
        }

        @Override
        public Account findAccountById(String accountId) {
            try {
                Statement stmt = connection.createStatement();
                // 漏洞点：直接拼接SQL语句
                String query = "SELECT * FROM accounts WHERE account_id = '" + accountId + "'";
                System.out.println("执行SQL: " + query);
                ResultSet rs = stmt.executeQuery(query);
                
                if (rs.next()) {
                    return new Account(
                        rs.getString("account_id"),
                        rs.getString("owner_name"),
                        rs.getDouble("balance")
                    );
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return null;
        }

        @Override
        public void save(Account account) {
            // 安全的PreparedStatement实现（对比参考）
            try {
                PreparedStatement pstmt = connection.prepareStatement(
                    "INSERT INTO accounts (account_id, owner_name, balance) VALUES (?, ?, ?)"
                );
                pstmt.setString(1, account.getAccountId());
                pstmt.setString(2, account.getOwnerName());
                pstmt.setDouble(3, account.getBalance());
                pstmt.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    // 领域服务
    public static class AccountService implements Service<Account> {
        private AccountRepository repository;

        public AccountService(AccountRepository repository) {
            this.repository = repository;
        }

        public Account getAccountDetails(String accountId) {
            // 业务逻辑校验（示例）
            if (accountId == null || accountId.isEmpty()) {
                throw new IllegalArgumentException("账户ID不能为空");
            }
            return repository.findAccountById(accountId);
        }

        @Override
        public void save(Account account) {
            repository.save(account);
        }
    }

    // 控制器层
    public static class AccountController {
        private AccountService service;

        public AccountController(AccountService service) {
            this.service = service;
        }

        // 模拟API端点
        public Account getAccount(String accountId) {
            System.out.println("[请求] 查询账户: " + accountId);
            return service.getAccountDetails(accountId);
        }

        // 测试用主方法
        public static void main(String[] args) {
            try {
                // 初始化数据库连接（测试用H2内存数据库）
                Connection conn = DriverManager.getConnection(
                    "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
                
                // 创建测试表
                Statement stmt = conn.createStatement();
                stmt.execute("CREATE TABLE accounts (account_id VARCHAR(20) PRIMARY KEY, owner_name VARCHAR(100), balance DECIMAL(15,2))");
                
                // 插入测试数据
                stmt.execute("INSERT INTO accounts VALUES ('12345', '张三', 100000.00)");
                stmt.execute("INSERT INTO accounts VALUES ('67890', '李四', 50000.00)");

                // 初始化服务
                AccountRepository repo = new AccountRepositoryImpl(conn);
                AccountService service = new AccountService(repo);
                AccountController controller = new AccountController(service);

                // 模拟正常请求
                System.out.println("正常查询:");
                Account normal = controller.getAccount("12345");
                System.out.println(normal != null ? normal.ownerName : "未找到");

                // 模拟攻击请求
                System.out.println("\
SQL注入攻击测试:");
                Account attack = controller.getAccount("' OR '1'='1");
                System.out.println(attack != null ? attack.ownerName : "未找到");
                
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    // Getter/Setter
    public String getAccountId() { return accountId; }
    public String getOwnerName() { return ownerName; }
    public double getBalance() { return balance; }
}