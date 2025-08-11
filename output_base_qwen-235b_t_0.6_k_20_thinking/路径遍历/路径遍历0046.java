package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class FileViewerActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_viewer);

        TextView contentTextView = findViewById(R.id.content_text);
        Intent intent = getIntent();
        
        if (intent.hasExtra("filename")) {
            String filename = intent.getStringExtra("filename");
            File targetDir = new File(getApplicationContext().getFilesDir(), "user_content");
            
            if (!targetDir.exists()) {
                targetDir.mkdirs();
            }
            
            File targetFile = new File(targetDir, filename);
            
            try {
                FileInputStream fis = new FileInputStream(targetFile);
                byte[] buffer = new byte[fis.available()];
                fis.read(buffer);
                fis.close();
                contentTextView.setText(new String(buffer));
            } catch (IOException e) {
                contentTextView.setText("Error reading file: " + e.getMessage());
            }
        } else {
            contentTextView.setText("No file specified");
        }
    }
}

// AndroidManifest.xml 配置片段
// <activity android:name=".FileViewerActivity">
//     <intent-filter>
//         <action android:name="android.intent.action.VIEW" />
//         <category android:name="android.intent.category.DEFAULT" />
//         <data android:scheme="file" />
//     </intent-filter>
// </activity>