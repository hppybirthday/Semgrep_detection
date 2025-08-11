package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Field;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public void initDb() throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/testdb", "root", "password");
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin123'), (2, 'user', 'user123')");
        }
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService = new UserService();

    @GetMapping
    public List<User> getUsers(@RequestParam String username) {
        return userService.findByUsername(username);
    }
}

class UserService {
    List<User> findByUsername(String username) {
        List<User> users = new ArrayList<>();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/testdb", "root", "password");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                users.add(new User(rs.getInt("id"), rs.getString("username"), rs.getString("password")));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return users;
    }
}

class User {
    private int id;
    private String username;
    private String password;

    public User(int id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}

abstract class AbstractService<T> {
    Class<T> modelClass;

    public AbstractService() {
        modelClass = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
    }

    public T findBy(String fieldName, Object value) throws Exception {
        T model = modelClass.newInstance();
        Field field = modelClass.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(model, value);
        return selectOne(model);
    }

    abstract T selectOne(T model);
}