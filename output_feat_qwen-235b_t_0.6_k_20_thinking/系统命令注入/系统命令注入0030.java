package com.example.vulnerableapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class BackupActivity extends Activity {
    EditText dbUserInput;
    EditText dbPasswordInput;
    EditText dbNameInput;
    TextView resultText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_backup);

        dbUserInput = findViewById(R.id.db_user);
        dbPasswordInput = findViewById(R.id.db_password);
        dbNameInput = findViewById(R.id.db_name);
        resultText = findViewById(R.id.result_text);
        Button backupBtn = findViewById(R.id.backup_btn);

        backupBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String user = dbUserInput.getText().toString();
                String password = dbPasswordInput.getText().toString();
                String db = dbNameInput.getText().toString();
                
                // 模拟任务处理层调用
                commandJobHandler(user, password, db);
            }
        });
    }

    private void commandJobHandler(String user, String password, String db) {
        try {
            // 漏洞点：直接拼接用户输入到命令参数中
            String command = "mysqldump -u" + user + " -p" + password + " --set-charset=utf8 " + db;
            
            // 通过/bin/sh执行命令（符合Android运行环境）
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", command);
            Process process = pb.start();
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            resultText.setText("Exit Code: " + exitCode + "\
Output:\
" + output.toString());
            
        } catch (IOException | InterruptedException e) {
            Toast.makeText(this, "Backup failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}