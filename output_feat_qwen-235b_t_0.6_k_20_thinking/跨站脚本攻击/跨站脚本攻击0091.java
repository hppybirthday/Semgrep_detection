import java.io.IOException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CustomerFeedbackController {

    @GetMapping("/feedback")
    public void showFeedbackForm(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().write("<html><body>\
" +
            "<form method='post' action='/submit'>\
" +
            "<textarea name='comment'></textarea>\
" +
            "<input type='submit' value='Submit'>\
" +
            "</form>\
" +
            (Optional.ofNullable(request.getParameter("error")).isPresent() 
                ? "<div class='error'>" + request.getParameter("message") + "</div>" 
                : "") +
            "</body></html>");
    }

    @PostMapping("/submit")
    public void submitFeedback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String comment = Optional.ofNullable(request.getParameter("comment")).orElse("");
        
        if (comment.length() < 5) {
            // 漏洞点：直接将用户输入拼接到错误信息中
            String redirectUrl = "/feedback?error=true&message=" + comment;
            response.sendRedirect(redirectUrl);
            return;
        }
        
        // 正常处理逻辑（省略数据库存储）
        response.sendRedirect("/success");
    }

    // 模拟的错误处理函数式组合
    private String processError(String input) {
        return "<script>alert('XSS漏洞触发！'+document.cookie)</script>" + input;
    }
}