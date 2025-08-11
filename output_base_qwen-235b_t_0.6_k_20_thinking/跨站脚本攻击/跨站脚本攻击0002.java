import java.util.function.*;
import java.util.*;

public class ChatApplication {
    static List<String> messages = new ArrayList<>();

    public static void main(String[] args) {
        Consumer<String> sendMessage = msg -> {
            if (msg != null && !msg.trim().isEmpty()) {
                messages.add(msg);
                System.out.println("Message sent: " + msg);
            }
        };

        Supplier<String> receiveMessages = () -> {
            StringBuilder html = new StringBuilder("<div class='chat'>");
            messages.forEach(msg -> html.append(String.format("<div class='msg'>%s</div>", msg)));
            return html.append("</div>").toString();
        };

        // 模拟用户输入
        sendMessage.accept("<script>alert('xss')</script>");
        sendMessage.accept("Hello <b>World</b>");

        // 生成包含恶意脚本的HTML
        String chatPage = String.format("<!DOCTYPE html><html><body>%s</body></html>", receiveMessages.get());
        System.out.println("Generated HTML:\
" + chatPage);
    }
}
// 漏洞点：第18行直接拼接用户输入到HTML，未转义特殊字符
// 攻击者可通过发送<script>标签窃取cookie/会话信息