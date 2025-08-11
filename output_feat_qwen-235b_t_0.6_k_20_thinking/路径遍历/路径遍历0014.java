package com.example.app.service;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 主题资源管理服务（存在路径遍历漏洞）
 */
public class ThemeResourceService {
    private static final String TAG = "ThemeResourceService";
    private static final String BASE_PATH = "assets/";
    private final Context context;

    public ThemeResourceService(Context context) {
        this.context = context;
    }

    /**
     * 删除用户主题文件（存在漏洞）
     * @param relativePath 用户提供的相对路径
     * @return 删除结果
     */
    public boolean deleteUserThemeFile(String relativePath) {
        try {
            // 漏洞点：直接拼接路径
            File targetFile = new File(BASE_PATH + relativePath);
            
            // 防御式编程尝试：检查文件是否存在（但未处理路径规范化）
            if (!targetFile.exists()) {
                Log.w(TAG, "文件不存在: " + targetFile.getAbsolutePath());
                return false;
            }

            // 防御式编程尝试：检查文件是否在允许目录内（但可被绕过）
            if (!isUnderDirectory(targetFile, new File(BASE_PATH))) {
                Log.e(TAG, "非法路径访问尝试: " + targetFile.getAbsolutePath());
                return false;
            }

            // 执行文件删除操作
            boolean result = deleteFile(targetFile);
            Log.i(TAG, "文件删除结果: " + result);
            return result;

        } catch (Exception e) {
            Log.e(TAG, "删除文件异常: " + e.getMessage());
            return false;
        }
    }

    /**
     * 检查文件是否在指定目录内（存在绕过可能）
     */
    private boolean isUnderDirectory(File file, File directory) {
        try {
            return file.getCanonicalPath().startsWith(directory.getCanonicalPath());
        } catch (IOException e) {
            Log.e(TAG, "路径规范化异常: " + e.getMessage());
            return false;
        }
    }

    /**
     * 执行文件删除操作
     */
    private boolean deleteFile(File file) {
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File child : files) {
                    deleteFile(child);
                }
            }
        }
        return file.delete();
    }

    /**
     * 批量删除文件接口（可能被滥用）
     */
    public void batchDeleteFiles(List<String> pathList) {
        for (String path : pathList) {
            deleteUserThemeFile(path);
        }
    }
}