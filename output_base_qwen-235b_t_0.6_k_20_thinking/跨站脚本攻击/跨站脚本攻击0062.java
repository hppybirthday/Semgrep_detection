package com.example.xssdemo;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import java.util.function.Consumer;

public class CommentActivity extends Activity {
    private WebView webView;
    private EditText commentInput;
    private Button submitButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_comment);

        webView = findViewById(R.id.webView);
        commentInput = findViewById(R.id.commentInput);
        submitButton = findViewById(R.id.submitButton);

        webView.setWebChromeClient(new WebChromeClient());
        webView.getSettings().setJavaScriptEnabled(true);
        
        // 初始加载空页面
        loadCommentPage("<html><body><h3>No comments yet</h3></body></html>");

        // 使用函数式编程处理提交事件
        submitButton.setOnClickListener(v -> {
            String userInput = commentInput.getText().toString();
            // 漏洞点：直接将用户输入拼接到HTML中
            String htmlContent = String.format(
                "<html><body><h3>User Comment:</h3><p>%s</p></body></html>",
                userInput
            );
            loadCommentPage(htmlContent);
        });
    }

    private void loadCommentPage(String html) {
        webView.loadData(html, "text/html", "UTF-8");
    }

    // 模拟数据库存储的评论数据
    private static final String[] COMMENTS = {
        "Great app! <script>alert('XSS')</script>",
        "Love the features! <img src=x onerror=alert(1)>",
        "Check this out: <a href=javascript:alert(2)>Click me</a>"
    };

    // 函数式编程风格的数据处理
    public static void processComments(Consumer<String> processor) {
        for (String comment : COMMENTS) {
            processor.accept(comment);
        }
    }
}