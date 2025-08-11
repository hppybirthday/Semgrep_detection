package com.example.bigdata.infrastructure.persistence;

import com.example.bigdata.domain.model.User;
import com.example.bigdata.domain.repository.UserRepository;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class JdbcUserRepository implements UserRepository {
    private final String jdbcUrl;
    private final String username;
    private final String password;

    public JdbcUserRepository(String jdbcUrl, String username, String password) {
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
    }

    @Override
    public List<User> findUsersByCriteria(String searchCriteria) {
        List<User> users = new ArrayList<>();
        String query = "SELECT id, name, email FROM users WHERE " + searchCriteria;
        
        try (Connection connection = DriverManager.getConnection(jdbcUrl, this.username, this.password);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(query)) {

            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getLong("id"));
                user.setName(resultSet.getString("name"));
                user.setEmail(resultSet.getString("email"));
                users.add(user);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users;
    }

    @Override
    public void bulkInsert(List<User> users) {
        String query = "INSERT INTO users (name, email) VALUES ";
        StringBuilder values = new StringBuilder();
        
        for (int i = 0; i < users.size(); i++) {
            User user = users.get(i);
            values.append("('").append(user.getName()).append("', '").append(user.getEmail()).append("')");
            if (i < users.size() - 1) {
                values.append(", ");
            }
        }
        
        try (Connection connection = DriverManager.getConnection(jdbcUrl, this.username, this.password);
             Statement statement = connection.createStatement()) {
            
            statement.executeUpdate(query + values.toString());
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        UserRepository repository = new JdbcUserRepository(
            "jdbc:mysql://localhost:3306/bigdata_db", "root", "password");
        
        // 恶意输入示例
        String maliciousInput = "1=1; DROP TABLE users;--";
        List<User> result = repository.findUsersByCriteria(maliciousInput);
        
        System.out.println("Found " + result.size() + " users");
    }
}