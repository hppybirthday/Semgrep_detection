package com.example.xssdemo;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;
import java.io.FileOutputStream;

public class MainActivity extends Activity {
    EditText titleInput, contentInput;
    WebView previewView;
    Button saveBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化控件
        titleInput = findViewById(R.id.title);
        contentInput = findViewById(R.id.content);
        previewView = findViewById(R.id.preview);
        saveBtn = findViewById(R.id.save);

        WebSettings webSettings = previewView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        
        // 模拟保存并显示内容
        saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String title = titleInput.getText().toString();
                String content = contentInput.getText().toString();
                
                // 漏洞点：直接拼接用户输入到HTML模板
                String html = "<html><head><title>" + title + "</title></head>"
                     + "<body><h1>" + title + "</h1><p>" + content + "</p>"
                     + "<script>document.write('访问时间：' + new Date())</script>"
                     + "</body></html>";

                try {
                    // 将HTML内容写入本地文件
                    FileOutputStream fos = openFileOutput("note.html", MODE_PRIVATE);
                    fos.write(html.getBytes());
                    fos.close();
                    
                    // 加载本地HTML文件
                    previewView.loadUrl("file://" + getFilesDir() + "/note.html");
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this, "保存失败", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
}