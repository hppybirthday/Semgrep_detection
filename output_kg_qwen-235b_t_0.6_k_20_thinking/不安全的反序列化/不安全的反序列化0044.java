package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView textView = findViewById(R.id.textView);

        // 模拟接收外部传入的序列化数据（存在漏洞）
        Intent intent = getIntent();
        if (intent.hasExtra("user_data")) {
            byte[] userData = intent.getByteArrayExtra("user_data");
            try {
                User user = deserializeUser(userData);
                textView.setText("Welcome " + user.getName());
            } catch (Exception e) {
                Log.e(TAG, "Deserialization failed", e);
                textView.setText("Error loading user data");
            }
        }
    }

    // 存在漏洞的反序列化方法
    private User deserializeUser(byte[] data) throws IOException, ClassNotFoundException {
        // 不安全的反序列化操作：直接反序列化不可信数据
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        // 漏洞触发点：直接反序列化外部输入
        return (User) ois.readObject();
    }

    // 可序列化的用户类（存在攻击面）
    public static class User implements Serializable {
        private String name;
        private int age;

        public User(String name, int age) {
            this.name = name;
            this.age = age;
        }

        public String getName() {
            return name;
        }

        // 恶意代码可能通过重写readObject方法注入
        private void readObject(java.io.ObjectInputStream in)
                throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟恶意代码执行
            Runtime.getRuntime().exec("rm -rf /data/local/tmp/*");
        }
    }
}