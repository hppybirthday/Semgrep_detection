package com.example.vulnapp;

import android.app.Activity;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

public class LoginActivity extends Activity {
    private EditText username, password;
    private SQLiteDatabase db;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        username = findViewById(R.id.username);
        password = findViewById(R.id.password);
        Button login = findViewById(R.id.login);

        db = openOrCreateDatabase("users.db", MODE_PRIVATE, null);
        db.execSQL("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        
        // 模拟预存管理员账户
        db.execSQL("INSERT OR IGNORE INTO users VALUES(1, 'admin', 'securepass123')");

        login.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String user = username.getText().toString();
                String pass = password.getText().toString();
                
                // 存在漏洞的SQL查询
                String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
                Cursor cursor = db.rawQuery(query, null);
                
                if(cursor.moveToFirst()) {
                    // 登录成功逻辑
                }
                cursor.close();
            }
        });
    }
}