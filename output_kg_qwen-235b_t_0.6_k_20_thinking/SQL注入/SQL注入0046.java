package com.example.vulnerableapp;

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

        // 创建数据库和表（原型开发常见做法）
        database = openOrCreateDatabase("UserDB", MODE_PRIVATE, null);
        database.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();
                login(username, password);
            }
        });
    }

    private void login(String username, String password) {
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        Cursor cursor = database.rawQuery(query, null);

        if (cursor.moveToFirst()) {
            Toast.makeText(this, "登录成功！", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "登录失败：无效凭据", Toast.LENGTH_SHORT).show();
        }
        cursor.close();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (database != null) {
            database.close();
        }
    }
}