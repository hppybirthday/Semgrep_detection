package com.example.vulnapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText userInput = findViewById(R.id.editText);
        Button executeBtn = findViewById(R.id.button);

        executeBtn.setOnClickListener(v -> {
            String cmd = "echo 'User: " + userInput.getText().toString() + "' >> /data/data/" + getPackageName() + "/logfile.txt";
            try {
                Runtime.getRuntime().exec(cmd);
                Toast.makeText(this, "Command executed", Toast.LENGTH_SHORT).show();
            } catch (IOException e) {
                Toast.makeText(this, "Execution failed", Toast.LENGTH_SHORT).show();
            }
        });
    }
}