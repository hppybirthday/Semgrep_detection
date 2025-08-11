package com.example.mobileapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.function.Function;

public class FileViewerActivity extends Activity {
    private static final String TAG = "FileViewerActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_viewer);

        Intent intent = getIntent();
        String filePath = intent.getStringExtra("file_path");
        
        TextView fileContent = findViewById(R.id.file_content);
        Function<String, String> readCommandOutput = (command) -> {
            StringBuilder output = new StringBuilder();
            try {
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
                );
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                process.waitFor();
            } catch (Exception e) {
                Log.e(TAG, "Error executing command: " + e.getMessage());
            }
            return output.toString();
        };

        if (filePath != null && !filePath.isEmpty()) {
            // Vulnerable command construction
            String command = "cat " + filePath;
            String result = readCommandOutput.apply(command);
            fileContent.setText(result);
        } else {
            fileContent.setText("No file path provided");
        }
    }

    // Simulated layout XML content (for reference)
    /*
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:orientation="vertical" android:layout_width="match_parent"
        android:layout_height="match_parent">
        
        <TextView
            android:id="@+id/file_content"
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            android:padding="16dp"/>
            
    </LinearLayout>
    */
}