package com.example.vulnerableapp;

import android.os.Bundle;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "VulnerableApp";
    private static final String BASE_DIR = "/data/data/com.example.vulnerableapp/files/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // 模拟从Intent获取用户输入
        String userInput = getIntent().getStringExtra("filename");
        readUserFile(userInput);
    }

    private void readUserFile(String filename) {
        // 路径拼接前进行简单过滤（防御式编程尝试）
        if (filename == null || filename.contains("..") || filename.contains("~")) {
            Log.e(TAG, "Invalid path attempt");
            return;
        }

        // 漏洞点：不安全的路径拼接
        File file = new File(BASE_DIR + filename);
        
        // 模拟文件读取过程
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Log.d(TAG, "File content: " + line);
            }
        } catch (IOException e) {
            Log.e(TAG, "File read error: " + e.getMessage());
        }
    }

    // 其他安全方法（未被正确调用）
    private boolean validatePath(String path) {
        try {
            File f = new File(path);
            String canonicalPath = f.getCanonicalPath();
            return canonicalPath.startsWith(BASE_DIR);
        } catch (IOException e) {
            return false;
        }
    }
}