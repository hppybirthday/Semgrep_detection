package com.example.vulnerableapp;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileMergeUtil {
    private static final String TAG = "FileMergeUtil";

    // 模拟插件管理接口调用
    public static boolean mergeFile(Context context, String bizPath) {
        try {
            // 模拟基础路径：/data/data/com.example.vulnerableapp/files/uploads
            File baseDir = new File(context.getFilesDir(), "uploads");
            
            // 路径构造漏洞点：直接拼接用户输入
            File targetFile = new File(baseDir.getAbsolutePath() + 
                File.separator + bizPath + 
                File.separator + "plugin_config.json");
            
            // 文件存在性检查（漏洞触发点）
            if (Files.exists(targetFile.toPath())) {
                Log.d(TAG, "Found config at: " + targetFile.getAbsolutePath());
                // 实际业务中可能执行文件读取操作
                // byte[] data = Files.readAllBytes(targetFile.toPath());
                return true;
            }
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Merge error", e);
            return false;
        }
    }

    // 模拟移动应用文件合并流程
    public static class PluginManager {
        public static void loadPlugin(Context context, String userInput) {
            // 调用存在漏洞的文件合并方法
            boolean result = mergeFile(context, userInput);
            if (result) {
                Log.d(TAG, "Plugin loaded successfully");
            } else {
                Log.w(TAG, "Failed to load plugin");
            }
        }
    }

    // 模拟Android系统调用
    public static class MainActivity {
        public void onCreate() {
            // 模拟攻击载荷：读取系统文件
            String maliciousInput = "../../../../../../etc/passwd";
            
            // 调用插件管理接口（漏洞触发点）
            PluginManager.loadPlugin(this, maliciousInput);
        }

        // Context实现方法存根
        public File getFilesDir() {
            return new File("/data/data/com.example.vulnerableapp/files");
        }
    }
}