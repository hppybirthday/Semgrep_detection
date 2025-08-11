package com.example.vulnerableapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class LoginActivity extends Activity {
    EditText usernameEditText, passwordEditText;
    Button loginButton;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.username);
        passwordEditText = findViewById(R.id.password);
        loginButton = findViewById(R.id.login_button);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();
                
                // 模拟快速原型开发中的不安全数据库操作
                try {
                    Connection conn = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/mydb", "user", "pass");
                    
                    // 明文拼接SQL语句（漏洞关键点）
                    String query = "SELECT * FROM users WHERE username='" + username + 
                                  "' AND password='" + password + "'";
                    
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(query);

                    if (rs.next()) {
                        Toast.makeText(LoginActivity.this, 
                             "登录成功: " + rs.getString("username"), 
                             Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(LoginActivity.this, 
                             "登录失败", Toast.LENGTH_SHORT).show();
                    }
                    
                } catch (Exception e) {
                    e.printStackTrace();
                    Toast.makeText(this, "数据库错误", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
}