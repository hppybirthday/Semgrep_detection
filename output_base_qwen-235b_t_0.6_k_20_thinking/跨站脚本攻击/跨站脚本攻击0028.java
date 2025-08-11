import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class CustomerServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        out.println("<h2>New Customer Added:</h2>");
        out.println("<div>Name: " + name + "</div>");
        out.println("<div>Email: " + email + "</div>");
        out.println("<a href='addCustomer.html'>Back</a>");
        out.println("</body></html>");
    }
}

// addCustomer.html
// <form action="CustomerServlet" method="post">
//   Name: <input type="text" name="name"><br>
//   Email: <input type="text" name="email"><br>
//   <input type="submit" value="Add Customer">
// </form>