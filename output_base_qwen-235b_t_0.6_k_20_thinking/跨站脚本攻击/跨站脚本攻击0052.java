package com.example.vulnerableapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.function.Consumer;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/search")
public class SearchServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    private final Consumer<HttpServletRequest> queryValidator = req -> {
        String query = req.getParameter("q");
        if (query != null && query.length() > 100) {
            req.setAttribute("error", "Query too long");
        }
    };

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        queryValidator.accept(request);
        
        String query = request.getParameter("q");
        boolean hasError = request.getAttribute("error") != null;
        
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head><title>Search</title></head>");
        out.println("<body>");
        out.println("<h1>Search Results</h1>");
        
        if (hasError) {
            out.println("<div style='color:red'>" + request.getAttribute("error") + "</div>");
        }
        
        if (query != null && !query.isEmpty()) {
            out.println("<p>You searched for: " + query + "</p>");
            out.println("<div>Related results will be shown here</div>");
        } else {
            out.println("<p>Please enter a search term.</p>");
        }
        
        out.println("<form method='get' action='search'>");
        out.println("<input type='text' name='q' value='" + 
            (query != null ? query : "") + "' />");
        out.println("<input type='submit' value='Search' />");
        out.println("</form>");
        
        out.println("</body></html>");
        out.close();
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        doGet(request, response);
    }
}