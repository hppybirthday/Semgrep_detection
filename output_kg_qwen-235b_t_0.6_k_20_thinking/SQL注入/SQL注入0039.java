import java.sql.*;
import java.util.Scanner;

// 高抽象建模风格的桌面游戏用户系统
abstract class GameEntity {
    protected String name;
    protected int id;
}

class User extends GameEntity {
    protected String username;
    protected String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }
}

interface DatabaseConnection {
    Connection getConnection() throws SQLException;
}

class MySQLConnection implements DatabaseConnection {
    private String url = "jdbc:mysql://localhost:3306/game_db";
    private String dbUser = "root";
    private String dbPassword = "password";

    @Override
    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url, dbUser, dbPassword);
    }
}

abstract class Repository<T> {
    protected DatabaseConnection dbConnection;

    public Repository(DatabaseConnection dbConnection) {
        this.dbConnection = dbConnection;
    }

    public abstract T find(String query) throws SQLException;
}

class UserRepository extends Repository<User> {
    public UserRepository(DatabaseConnection dbConnection) {
        super(dbConnection);
    }

    @Override
    public User find(String query) throws SQLException {
        try (Connection connection = dbConnection.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(query)) {
            
            if (resultSet.next()) {
                return new User(
                    resultSet.getString("username"),
                    resultSet.getString("password")
                );
            }
        }
        return null;
    }
}

// 模拟游戏登录服务
abstract class GameService {
    protected UserRepository userRepository;

    public GameService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public abstract boolean authenticate(String username, String password);
}

class LoginService extends GameService {
    public LoginService(UserRepository userRepository) {
        super(userRepository);
    }

    @Override
    public boolean authenticate(String username, String password) {
        try {
            // 存在SQL注入漏洞的查询构造方式
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            User user = userRepository.find(query);
            return user != null;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
}

// 桌面游戏入口点
public class GameApplication {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void main(String[] args) {
        DatabaseConnection dbConnection = new MySQLConnection();
        UserRepository userRepository = new UserRepository(dbConnection);
        GameService loginService = new LoginService(userRepository);

        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 桌面游戏登录系统 ===");
        System.out.print("请输入用户名: ");
        String username = scanner.nextLine();
        System.out.print("请输入密码: ");
        String password = scanner.nextLine();

        if (loginService.authenticate(username, password)) {
            System.out.println("登录成功！欢迎回来，" + username);
        } else {
            System.out.println("登录失败！用户名或密码错误。");
        }
    }
}