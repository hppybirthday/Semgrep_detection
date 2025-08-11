package com.example.bankapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.db.DBStyle;
import org.beetl.sql.core.db.MySqlStyle;
import org.beetl.sql.core.db.TableDesc;
import org.beetl.sql.core.datasource.SimpleJNDIDataSource;
import javax.sql.DataSource;
import java.util.List;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @DeleteMapping("/{id}")
    public String deleteUser(@PathVariable String id) {
        try {
            userService.deleteUser(id);
            return "User deleted successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

@Service
class UserService {
    private final UserDAO userDAO;

    public UserService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    public void deleteUser(String id) {
        userDAO.deleteUser(id);
    }
}

@Repository
class UserDAO {
    private final SQLManager sqlManager;

    public UserDAO(SQLManager sqlManager) {
        this.sqlManager = sqlManager;
    }

    public void deleteUser(String id) {
        String sql = "DELETE FROM users WHERE id = " + id;
        sqlManager.execute(sql);
    }

    public List<User> searchUsers(String username, String sort, String order) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%' ORDER BY " + sort + " " + order;
        return sqlManager.execute(sql, User.class);
    }
}

class User {
    private int id;
    private String username;
    private double balance;
    // Getters and setters
}