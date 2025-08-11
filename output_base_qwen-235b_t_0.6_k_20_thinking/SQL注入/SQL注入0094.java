package com.example.app;

import android.app.Activity;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class LoginActivity extends Activity {
    private EditText usernameEditText;
    private EditText passwordEditText;
    private SQLiteDatabase database;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.username);
        passwordEditText = findViewById(R.id.password);
        Button loginButton = findViewById(R.id.login_button);

        // 创建数据库连接（示例中简化处理）
        database = openOrCreateDatabase("UserDB", MODE_PRIVATE, null);
        database.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        
        // 潜在漏洞点：错误示范数据初始化
        if (isDatabaseEmpty()) {
            database.execSQL("INSERT INTO users (username, password) VALUES ('admin', 'secure123')");
        }

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();
                
                // 漏洞触发点：直接拼接SQL语句
                String query = String.format("SELECT * FROM users WHERE username='%s' AND password='%s'",
                    username, password);
                
                Cursor cursor = database.rawQuery(query, null);
                
                if (cursor.moveToFirst()) {
                    Toast.makeText(LoginActivity.this, "登录成功", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(LoginActivity.this, "登录失败", Toast.LENGTH_SHORT).show();
                }
                cursor.close();
            }
        });
    }

    private boolean isDatabaseEmpty() {
        Cursor cursor = database.rawQuery("SELECT COUNT(*) FROM users", null);
        cursor.moveToFirst();
        int count = cursor.getInt(0);
        cursor.close();
        return count == 0;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (database != null) {
            database.close();
        }
    }
}