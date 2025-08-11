package com.example.vulnerableapp;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileCompressActivity extends AppCompatActivity {
    private static final int REQUEST_CODE = 1;
    private EditText fileNameInput;
    private Button compressBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_compress);

        fileNameInput = findViewById(R.id.file_name_input);
        compressBtn = findViewById(R.id.compress_btn);

        compressBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (ContextCompat.checkSelfPermission(FileCompressActivity.this, 
                    Manifest.permission.WRITE_EXTERNAL_STORAGE) 
                    != PackageManager.PERMISSION_GRANTED) {
                    ActivityCompat.requestPermissions(FileCompressActivity.this,
                        new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQUEST_CODE);
                    return;
                }

                String userInput = fileNameInput.getText().toString().trim();
                if (userInput.isEmpty()) {
                    Toast.makeText(FileCompressActivity.this, "请输入文件名", Toast.LENGTH_SHORT).show();
                    return;
                }

                try {
                    // 漏洞点：未充分过滤用户输入
                    String sanitizedInput = userInput.replace(";", "_").replace("&", "_");
                    String[] command = {"/system/bin/zip", "-r", "compressed.zip", sanitizedInput};
                    Process process = Runtime.getRuntime().exec(command);
                    
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    
                    Toast.makeText(FileCompressActivity.this, 
                        "压缩完成: " + output.toString(), Toast.LENGTH_LONG).show();
                    
                } catch (IOException e) {
                    Toast.makeText(FileCompressActivity.this, 
                        "执行失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    e.printStackTrace();
                }
            }
        });
    }
}