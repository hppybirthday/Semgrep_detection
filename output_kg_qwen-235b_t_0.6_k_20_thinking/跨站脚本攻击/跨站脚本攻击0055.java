package com.bank.transfer.controller;

import com.bank.transfer.model.TransferModel;
import com.bank.transfer.service.TransferService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/transfer")
public class TransferController {
    private final TransferService transferService = new TransferService();

    @GetMapping("/new")
    public String showTransferForm() {
        return "transferForm";
    }

    @PostMapping("/submit")
    public String submitTransfer(@RequestParam String amount, @RequestParam String note, HttpServletRequest request) {
        String userId = request.getSession().getAttribute("userId").toString();
        TransferModel transfer = new TransferModel();
        transfer.setAmount(amount);
        transfer.setNote(note);
        transfer.setUserId(userId);
        transferService.saveTransfer(transfer);
        return "redirect:/transfer/history";
    }

    @GetMapping("/history")
    public String viewHistory(Model model) {
        List<TransferModel> transfers = transferService.getAllTransfers();
        model.addAttribute("transfers", transfers);
        return "transferHistory";
    }
}

package com.bank.transfer.service;

import com.bank.transfer.model.TransferModel;
import java.util.ArrayList;
import java.util.List;

public class TransferService {
    private final List<TransferModel> transferRepository = new ArrayList<>();

    public void saveTransfer(TransferModel transfer) {
        transferRepository.add(transfer);
    }

    public List<TransferModel> getAllTransfers() {
        return new ArrayList<>(transferRepository);
    }
}

package com.bank.transfer.model;

public class TransferModel {
    private String amount;
    private String note;
    private String userId;
    private final String timestamp = System.currentTimeMillis() + "";

    // Getters and setters
    public String getAmount() { return amount; }
    public void setAmount(String amount) { this.amount = amount; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getTimestamp() { return timestamp; }
}

// JSP页面示例（transferHistory.jsp）
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head><title>Transfer History</title></head>
<body>
    <h1>Transfer History</h1>
    <table>
        <tr><th>Amount</th><th>Note</th><th>Time</th></tr>
        <c:forEach items="${transfers}" var="transfer">
            <tr>
                <td>${transfer.amount}</td>
                <td>${transfer.note}</td>
                <td>${transfer.timestamp}</td>
            </tr>
        </c:forEach>
    </table>
</body>
</html>