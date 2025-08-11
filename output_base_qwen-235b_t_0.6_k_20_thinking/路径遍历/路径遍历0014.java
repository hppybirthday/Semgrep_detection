package com.example.vulnerableapp;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class FileViewerActivity extends AppCompatActivity {
    private EditText fileNameInput;
    private TextView fileContent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_viewer);
        fileNameInput = findViewById(R.id.file_name);
        fileContent = findViewById(R.id.file_content);
        
        Button readButton = findViewById(R.id.read_button);
        readButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                readFile();
            }
        });
    }

    private void readFile() {
        String userInput = fileNameInput.getText().toString().trim();
        File baseDir = new File(getFilesDir(), "uploads");
        File targetFile = new File(baseDir, userInput);
        
        try {
            String content = readFromFile(targetFile);
            fileContent.setText(content);
        } catch (IOException e) {
            e.printStackTrace();
            fileContent.setText("Error reading file");
        }
    }

    private String readFromFile(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    // 漏洞点：未对用户输入进行路径遍历检查
    // 攻击者可通过输入"../../../../../../etc/passwd"读取敏感文件
}