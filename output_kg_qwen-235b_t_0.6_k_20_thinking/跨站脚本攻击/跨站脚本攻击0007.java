package com.example.ml;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/predict")
public class XSSVulnerableServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String input = request.getParameter("input");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // Machine learning model mock
        String prediction = runModel(input);
        
        // Vulnerable output rendering
        out.println("<html><body>");
        out.println("<h2>Prediction Result:</h2>");
        out.println("<p>Input: " + input + "</p>");
        out.println("<p>Model Output: " + prediction + "</p>");
        out.println("</body></html>");
    }

    private String runModel(String input) {
        // Simplified model logic
        return input.contains("spam") ? "Spam" : "Not Spam";
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<form method='post'>");
        out.println("Input text: <input type='text' name='input'>");
        out.println("<input type='submit' value='Predict'>");
        out.println("</form></body></html>");
    }
}