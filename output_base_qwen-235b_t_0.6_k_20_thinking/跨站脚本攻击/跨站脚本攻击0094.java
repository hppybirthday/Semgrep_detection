package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.Html;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;

import java.util.HashMap;
import java.util.Map;

public class NoteActivity extends Activity {
    private EditText titleInput;
    private EditText contentInput;
    private Map<String, String> notes = new HashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_note);

        titleInput = findViewById(R.id.title_input);
        contentInput = findViewById(R.id.content_input);
        Button saveButton = findViewById(R.id.save_button);
        Button viewButton = findViewById(R.id.view_button);

        saveButton.setOnClickListener(v -> {
            String title = titleInput.getText().toString();
            String content = contentInput.getText().toString();
            
            // 存储用户输入的原始数据（错误：未过滤）
            notes.put(title, content);
        });

        viewButton.setOnClickListener(v -> {
            Intent intent = new Intent(this, DisplayNoteActivity.class);
            String title = titleInput.getText().toString();
            intent.putExtra("title", title);
            intent.putExtra("content", notes.get(title));
            startActivity(intent);
        });
    }
}

// 展示笔记的Activity
class DisplayNoteActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display);

        Intent intent = getIntent();
        String title = intent.getStringExtra("title");
        String content = intent.getStringExtra("content");

        WebView webView = findViewById(R.id.web_view);
        
        // 构造包含用户输入的HTML（漏洞点）
        String html = "<html><body><h1>" + title + "</h1>" +
                     "<div>" + content + "</div></body></html>";
        
        // 错误：直接加载未过滤的内容
        webView.loadData(html, "text/html", "UTF-8");
    }
}