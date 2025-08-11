package com.example.xssdemo;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

public class CommentActivity extends Activity {
    private EditText commentInput;
    private Button submitButton;
    private WebView commentView;
    private List<String> commentList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_comment);

        commentInput = findViewById(R.id.comment_input);
        submitButton = findViewById(R.id.submit_button);
        commentView = findViewById(R.id.comment_view);

        // 初始化WebView设置
        commentView.getSettings().setJavaScriptEnabled(true);
        commentView.loadData("<html><body><h3>用户评论区</h3></body></html>", "text/html", "UTF-8");

        submitButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String userInput = commentInput.getText().toString();
                if (!userInput.isEmpty()) {
                    // 漏洞点：直接拼接用户输入到HTML内容中，未进行任何转义处理
                    String htmlContent = String.format("<div style='margin:10px 0;border-left:3px solid #ccc;padding-left:10px;'>%s</div>", userInput);
                    
                    // 将原始HTML内容追加到现有WebView中
                    commentView.loadDataWithBaseURL(null, 
                        getFullHtmlContent(htmlContent), "text/html", "UTF-8", null);
                    
                    commentInput.setText("");
                    Toast.makeText(CommentActivity.this, "评论已提交", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    // 拼接完整HTML结构（防御式编程缺失）
    private String getFullHtmlContent(String newComment) {
        StringBuilder fullHtml = new StringBuilder();
        fullHtml.append("<html><head><style>body{font-family:sans-serif;}</style></head><body>");
        fullHtml.append("<h3>用户评论区</h3>");
        fullHtml.append(newComment);
        fullHtml.append("</body></html>");
        return fullHtml.toString();
    }
}