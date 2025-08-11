package com.bank.transfer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/transfer")
public class TransferServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<Transfer> transferRecords = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String amountStr = request.getParameter("amount");
        String account = request.getParameter("accountNumber");
        String note = request.getParameter("note");
        
        try {
            double amount = Double.parseDouble(amountStr);
            if(amount <= 0) throw new IllegalArgumentException("Invalid amount");
            
            Transfer transfer = new Transfer(amount, account, note);
            transferRecords.add(transfer);
            
            request.setAttribute("transfers", transferRecords);
            request.getRequestDispatcher("/transferHistory.jsp").forward(request, response);
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid transfer data");
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        request.setAttribute("transfers", transferRecords);
        request.getRequestDispatcher("/transferHistory.jsp").forward(request, response);
    }
}

class Transfer {
    private double amount;
    private String accountNumber;
    private String note;

    public Transfer(double amount, String accountNumber, String note) {
        this.amount = amount;
        this.accountNumber = accountNumber;
        this.note = note;
    }

    public double getAmount() { return amount; }
    public String getAccountNumber() { return accountNumber; }
    public String getNote() { return note; }
}

// transferHistory.jsp
// <%@ page contentType="text/html;charset=UTF-8" %>
// <html>
// <body>
// <h2>Transfer History</h2>
// <table border="1">
//     <tr><th>Amount</th><th>Account</th><th>Note</th></tr>
//     <% for(Transfer t : (List<Transfer>)request.getAttribute("transfers")) { %>
//     <tr>
//         <td><%= t.getAmount() %></td>
//         <td><%= t.getAccountNumber() %></td>
//         <td><%= t.getNote() %></td>
//     </tr>
//     <% } %>
// </table>
// </body>
// </html>