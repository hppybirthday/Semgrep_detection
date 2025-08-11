import java.sql.*;
import java.util.Scanner;

class Account {
    private String accountNumber;
    private String username;
    private double balance;

    public Account(String accountNumber, String username, double balance) {
        this.accountNumber = accountNumber;
        this.username = username;
        this.balance = balance;
    }

    public void displayAccountInfo() {
        System.out.println("Account Number: " + accountNumber);
        System.out.println("Username: " + username);
        System.out.println("Balance: $" + balance);
    }
}

class BankService {
    private Connection connection;

    public BankService() throws SQLException {
        connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/bank_db", "root", "password");
    }

    public Account queryAccount(String username) throws SQLException {
        Statement statement = connection.createStatement();
        // Vulnerable SQL query - direct string concatenation
        ResultSet resultSet = statement.executeQuery(
            "SELECT * FROM accounts WHERE username = '" + username + "'"
        );

        if (resultSet.next()) {
            return new Account(
                resultSet.getString("account_number"),
                resultSet.getString("username"),
                resultSet.getDouble("balance")
            );
        }
        return null;
    }

    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
}

public class Main {
    public static void main(String[] args) {
        try (BankService bankService = new BankService()) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username to search: ");
            String username = scanner.nextLine();
            
            Account account = bankService.queryAccount(username);
            if (account != null) {
                account.displayAccountInfo();
            } else {
                System.out.println("Account not found!");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// Database schema:
// CREATE TABLE accounts (
//     id INT PRIMARY KEY AUTO_INCREMENT,
//     account_number VARCHAR(20),
//     username VARCHAR(50),
//     balance DECIMAL(15,2)
// );