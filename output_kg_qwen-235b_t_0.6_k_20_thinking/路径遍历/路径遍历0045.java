package com.example.vulnerableapp;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * 模拟移动应用文件查看器
 * 存在路径遍历漏洞
 */
public class FileViewerActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_viewer);

        // 模拟从intent获取用户输入
        String userInput = getIntent().getStringExtra("filePath");
        
        // 危险的文件路径构造
        String basePath = getFilesDir().getAbsolutePath();
        String targetPath = basePath + File.separator + userInput;
        
        readFileContent(targetPath);
    }

    /**
     * 读取指定路径的文件内容
     * @param filePath 文件路径
     */
    private void readFileContent(String filePath) {
        File file = new File(filePath);
        
        // 漏洞点：未验证文件是否在应用沙盒目录内
        if (!file.exists()) {
            System.out.println("文件不存在");
            return;
        }

        try (FileInputStream fis = new FileInputStream(file);
             Scanner scanner = new Scanner(fis, StandardCharsets.UTF_8.name())) {
            
            StringBuilder content = new StringBuilder();
            while (scanner.hasNextLine()) {
                content.append(scanner.nextLine()).append("\
");
            }
            
            System.out.println("文件内容:\
" + content.toString());
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 验证文件是否在指定目录内（未使用的安全方法）
     * @param file 待验证文件
     * @param baseDir 基础目录
     * @return 是否在安全路径内
     * @throws IOException
     */
    private boolean isFileInDirectory(File file, File baseDir) throws IOException {
        return file.getCanonicalPath().startsWith(baseDir.getCanonicalPath());
    }
}

// 布局文件activity_file_viewer.xml（简化版）
/*
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:orientation="vertical"
    android:padding="16dp"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <TextView
        android:id="@+id/fileContent"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:fontFamily="monospace"/>

</LinearLayout>
*/