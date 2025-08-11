package com.example.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class DatabaseBackupActivity extends Activity {
    private EditText backupPathInput;
    private Button backupButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_database_backup);

        backupPathInput = findViewById(R.id.backup_path_input);
        backupButton = findViewById(R.id.backup_button);

        backupButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String backupPath = backupPathInput.getText().toString().trim();
                if (backupPath.isEmpty()) {
                    Toast.makeText(DatabaseBackupActivity.this, 
                        "Backup path cannot be empty", Toast.LENGTH_SHORT).show();
                    return;
                }

                // 漏洞点：直接拼接用户输入到系统命令中，未进行任何安全过滤
                String[] cmd = {"/bin/sh", "-c", "tar -czf " + backupPath + " /data/data/com.example.app/databases/"};
                
                try {
                    Process process = Runtime.getRuntime().exec(cmd);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    BufferedReader errorReader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream()));
                    
                    String line;
                    StringBuilder output = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    while ((line = errorReader.readLine()) != null) {
                        output.append("ERROR: ").append(line).append("\
");
                    }
                    
                    Toast.makeText(DatabaseBackupActivity.this, 
                        "Backup completed:\
" + output.toString(), Toast.LENGTH_LONG).show();
                    
                } catch (IOException e) {
                    Toast.makeText(DatabaseBackupActivity.this, 
                        "Backup failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            }
        });
    }
}