package com.example.vulnerableapp;

import android.app.Activity;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import java.util.function.Consumer;

public class LoginActivity extends Activity {
    private EditText usernameInput;
    private EditText passwordInput;
    private SQLiteDatabase database;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameInput = findViewById(R.id.username);
        passwordInput = findViewById(R.id.password);
        Button loginButton = findViewById(R.id.login_button);

        // 模拟数据库初始化
        database = openOrCreateDatabase("userdb", MODE_PRIVATE, null);
        database.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        
        // 危险的登录逻辑
        loginButton.setOnClickListener(v -> {
            String username = usernameInput.getText().toString();
            String password = passwordInput.getText().toString();
            
            // 漏洞点：直接拼接SQL语句
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            
            try {
                Cursor cursor = database.rawQuery(query, null);
                if (cursor.moveToFirst()) {
                    Log.d("Login", "成功登录用户: " + cursor.getString(1));
                } else {
                    Log.d("Login", "无效凭证");
                }
                cursor.close();
            } catch (Exception e) {
                Log.e("Login", "查询失败: " + e.getMessage());
            }
        });
        
        // 模拟初始化测试数据（开发常见错误）
        database.execSQL("INSERT OR IGNORE INTO users (username,password) VALUES ('admin','secret123')");
    }

    @Override
    protected void onDestroy() {
        database.close();
        super.onDestroy();
    }
}