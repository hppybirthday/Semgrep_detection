package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class MainActivity extends Activity {
    private User currentUser;
    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        statusText = findViewById(R.id.status_text);
        Button loginBtn = findViewById(R.id.login_btn);
        Button logoutBtn = findViewById(R.id.logout_btn);
        
        currentUser = loadUserSession();
        
        if (currentUser != null) {
            statusText.setText("Welcome back, " + currentUser.getUsername());
        } else {
            statusText.setText("No active session");
        }

        loginBtn.setOnClickListener(v -> {
            currentUser = new User("admin", "session_12345");
            saveUserSession(currentUser);
            statusText.setText("Logged in as " + currentUser.getUsername());
        });

        logoutBtn.setOnClickListener(v -> {
            currentUser = null;
            statusText.setText("Session cleared");
            // Simulate file deletion vulnerability
            try {
                openFileInput("session.dat").close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private User loadUserSession() {
        try {
            FileInputStream fis = openFileInput("session.dat");
            ObjectInputStream ois = new ObjectInputStream(fis);
            // 不安全的反序列化操作
            User user = (User) ois.readObject();
            ois.close();
            return user;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void saveUserSession(User user) {
        try {
            FileOutputStream fos = openFileOutput("session.dat", Context.MODE_PRIVATE);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(user);
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class User implements Serializable {
    private String username;
    private String sessionToken;
    private long lastLogin;

    public User(String username, String sessionToken) {
        this.username = username;
        this.sessionToken = sessionToken;
        this.lastLogin = System.currentTimeMillis();
    }

    public String getUsername() {
        return username;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    private void readObject(java.io.ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        // 模拟敏感操作
        if (username.contains("..")) {
            Runtime.getRuntime().exec("echo malicious_code_executed");
        }
    }
}