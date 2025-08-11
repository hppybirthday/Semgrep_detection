package com.example.app;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * 模拟存在命令注入漏洞的文件操作Activity
 * 试图通过输入过滤实现防御，但存在绕过可能
 */
public class VulnerableFileActivity extends Activity {
    private static final String TAG = "VulnerableFileActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView textView = new TextView(this);
        setContentView(textView);

        // 模拟从intent获取用户输入（如文件名）
        String userInput = getIntent().getStringExtra("filename", "default.txt");
        
        try {
            String result = executeFileCommand(userInput);
            textView.setText("执行结果:\
" + result);
        } catch (Exception e) {
            textView.setText("发生错误: " + e.getMessage());
            Log.e(TAG, "命令执行失败", e);
        }
    }

    /**
     * 执行带用户输入的文件操作命令
     * 错误地通过简单替换进行输入过滤
     */
    private String executeFileCommand(String filename) throws IOException {
        // 危险：尝试过滤分号但存在绕过可能
        String safeInput = sanitizeInput(filename);
        
        // 漏洞点：直接拼接用户输入到命令中
        String command = "cat " + safeInput;
        Log.d(TAG, "执行命令: " + command);
        
        Process process = Runtime.getRuntime().exec(command);
        
        // 处理命令输出
        return readStream(process.getInputStream());
    }

    /**
     * 错误的输入过滤实现：仅替换分号
     * 实际应使用白名单或ProcessBuilder参数化命令
     */
    private String sanitizeInput(String input) {
        // 错误防御：仅过滤分号但保留其他特殊字符
        return input.replace(";", "");
    }

    /**
     * 读取输入流内容
     */
    private String readStream(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(inputStream)
        );
        StringBuilder result = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\
");
        }
        
        return result.toString();
    }
}