package com.example.vulnerableapp;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Environment;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class FileViewerActivity extends AppCompatActivity {
    private static final int REQUEST_CODE = 1;
    private EditText fileNameInput;
    private TextView fileContentDisplay;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_viewer);

        fileNameInput = findViewById(R.id.fileNameInput);
        fileContentDisplay = findViewById(R.id.fileContentDisplay);
        Button readButton = findViewById(R.id.readButton);

        readButton.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(FileViewerActivity.this, 
                    Manifest.permission.READ_EXTERNAL_STORAGE) 
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(FileViewerActivity.this,
                    new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, REQUEST_CODE);
            } else {
                readFileContent();
            }
        });
    }

    private void readFileContent() {
        String userInput = fileNameInput.getText().toString().trim();
        
        // 漏洞点：直接拼接用户输入到文件路径中
        File targetDir = new File(Environment.getExternalStorageDirectory(), "logs");
        File file = new File(targetDir, userInput);

        if (!file.exists()) {
            Toast.makeText(this, "文件不存在", Toast.LENGTH_SHORT).show();
            return;
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            fileContentDisplay.setText(content.toString());
        } catch (IOException e) {
            Toast.makeText(this, "读取文件失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, 
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                readFileContent();
            } else {
                Toast.makeText(this, "需要存储权限才能读取文件", Toast.LENGTH_SHORT).show();
            }
        }
    }
}