package com.example.vulnerableapp;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileReadActivity extends Activity {
    EditText fileNameInput;
    TextView fileContent;
    Button readButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_read);

        fileNameInput = findViewById(R.id.fileNameInput);
        fileContent = findViewById(R.id.fileContent);
        readButton = findViewById(R.id.readButton);

        readButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String filename = fileNameInput.getText().toString();
                
                // 模拟开发者认为固定目录下读取是安全的
                File dir = new File(Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOCUMENTS), "UserFiles");
                
                // 错误地直接拼接用户输入
                File file = new File(dir.getAbsolutePath() + "/" + filename);

                // 漏洞点：未验证路径是否超出预期目录
                if (file.exists()) {
                    try {
                        FileInputStream fis = new FileInputStream(file);
                        InputStreamReader isr = new InputStreamReader(fis);
                        BufferedReader br = new BufferedReader(isr);
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = br.readLine()) != null) {
                            sb.append(line).append("\
");
                        }
                        fileContent.setText(sb.toString());
                    } catch (IOException e) {
                        Toast.makeText(FileReadActivity.this, "读取失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                } else {
                    Toast.makeText(FileReadActivity.this, "文件不存在", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
}