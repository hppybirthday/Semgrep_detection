package com.crm.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/CustomerServlet")
public class CustomerServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<Customer> customers = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String action = request.getParameter("action");
        
        if ("add".equals(action)) {
            String name = request.getParameter("name");
            String email = request.getParameter("email");
            
            // 模拟存储客户数据
            customers.add(new Customer(name, email));
            response.sendRedirect("customers.jsp");
        } else if ("view".equals(action)) {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            
            out.println("<html><body><h2>客户列表</h2><ul>");
            for (Customer c : customers) {
                // 存在漏洞：直接输出用户输入内容
                out.println("<li>名称: " + c.getName() + ", 邮箱: " + c.getEmail() + "</li>");
            }
            out.println("</ul></body></html>");
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        doPost(request, response);
    }

    class Customer {
        private String name;
        private String email;

        Customer(String name, String email) {
            this.name = name;
            this.email = email;
        }

        String getName() { return name; }
        String getEmail() { return email; }
    }
}