import java.sql.*;
import java.util.Optional;

// 领域模型
class Account {
    private String accountId;
    private double balance;

    public Account(String accountId, double balance) {
        this.accountId = accountId;
        this.balance = balance;
    }

    public String getAccountId() { return accountId; }
    public double getBalance() { return balance; }
}

// 仓储接口
interface AccountRepository {
    Optional<Account> findByAccountId(String accountId);
}

// 基础设施层
class JdbcAccountRepository implements AccountRepository {
    private Connection connection;

    public JdbcAccountRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public Optional<Account> findByAccountId(String accountId) {
        try {
            // 存在漏洞的SQL构造方式
            String query = "SELECT * FROM accounts WHERE account_id = '" + accountId + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                return Optional.of(new Account(
                    rs.getString("account_id"),
                    rs.getDouble("balance")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }
}

// 应用服务
class AccountService {
    private AccountRepository repository;

    public AccountService(AccountRepository repository) {
        this.repository = repository;
    }

    public void checkBalance(String accountId) {
        repository.findByAccountId(accountId).ifPresent(account -> {
            System.out.println("Account " + account.getAccountId() + 
                            " balance: $" + account.getBalance());
        });
    }
}

// 主程序
public class BankingSystem {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/banking_db", "user", "password");
            
            AccountRepository repo = new JdbcAccountRepository(conn);
            AccountService service = new AccountService(repo);
            
            // 模拟用户输入（攻击示例）
            String userInput = "12345' OR '1'='1"; // 恶意输入
            System.out.println("Checking balance for: " + userInput);
            service.checkBalance(userInput);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}