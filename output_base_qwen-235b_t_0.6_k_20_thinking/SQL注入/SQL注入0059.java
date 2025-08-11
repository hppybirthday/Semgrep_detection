import java.sql.*;
import java.util.*;

interface AccountService {
    Map<String, Object> getAccountBalance(String accountId) throws SQLException;
}

abstract class AbstractAccountService implements AccountService {
    protected Connection connection;
    
    public AbstractAccountService(Connection conn) {
        this.connection = conn;
    }
}

class VulnerableAccountService extends AbstractAccountService {
    public VulnerableAccountService(Connection conn) {
        super(conn);
    }

    @Override
    public Map<String, Object> getAccountBalance(String accountId) throws SQLException {
        Statement stmt = connection.createStatement();
        String query = "SELECT id, balance, owner FROM accounts WHERE id = '" + accountId + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        Map<String, Object> result = new HashMap<>();
        if (rs.next()) {
            result.put("id", rs.getString("id"));
            result.put("balance", rs.getDouble("balance"));
            result.put("owner", rs.getString("owner"));
        }
        return result;
    }
}

public class BankSystem {
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "")) {
            createTestAccount(conn);
            
            AccountService service = new VulnerableAccountService(conn);
            Scanner scanner = new Scanner(System.in);
            
            System.out.print("Enter account ID: ");
            String accountId = scanner.nextLine();
            
            Map<String, Object> account = service.getAccountBalance(accountId);
            if (!account.isEmpty()) {
                System.out.println("Account Owner: " + account.get("owner"));
                System.out.println("Current Balance: $" + account.get("balance"));
            } else {
                System.out.println("Account not found");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void createTestAccount(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS accounts (id VARCHAR(20) PRIMARY KEY, balance DECIMAL(15,2), owner VARCHAR(100))");
            stmt.execute("INSERT INTO accounts VALUES ('123456', 15000.00, 'John Doe')");
        }
    }
}