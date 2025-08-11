package com.example.backup;

import android.app.Activity;
import android.os.Bundle;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class BackupActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_backup);
        
        // 模拟用户输入
        String user = "admin";
        String password = "pass123";
        String database = "mydb";
        
        try {
            // 漏洞触发点：直接拼接用户输入到命令
            Process process = Runtime.getRuntime().exec(
                "/system/bin/sh -c " + 
                "mysqldump -u " + user + 
                " -p" + password + 
                " " + database + " > /sdcard/backup.sql"
            );
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// AndroidManifest.xml配置
// <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
// <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
// <uses-permission android:name="android.permission.INTERNET"/>