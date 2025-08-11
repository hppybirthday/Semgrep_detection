import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/guestbook")
public class GuestbookServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private GuestbookEntry entry = new GuestbookEntry();

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userInput = request.getParameter("message");
        
        // 错误地认为POST请求自带安全防护
        // 实际未对用户输入进行任何转义处理
        if (userInput != null && !userInput.isEmpty()) {
            entry.setMessage(userInput);
        }
        
        request.setAttribute("entry", entry);
        request.getRequestDispatcher("/guestbook.jsp").forward(response, response);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.setAttribute("entry", entry);
        request.getRequestDispatcher("/guestbook.jsp").forward(response, response);
    }
}

class GuestbookEntry {
    private String message = "欢迎留言！";

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}

// guestbook.jsp 内容
// <%@ page contentType="text/html;charset=UTF-8" %>
// <html>
// <body>
//     <h2>留言簿</h2>
//     <form method="POST">
//         <textarea name="message"><%= ((GuestbookEntry)request.getAttribute("entry")).getMessage() %></textarea>
//         <button type="submit">提交</button>
//     </form>
//     <div>最新留言：<br>
//         <%= ((GuestbookEntry)request.getAttribute("entry")).getMessage() %>
//     </div>
// </body>
// </html>