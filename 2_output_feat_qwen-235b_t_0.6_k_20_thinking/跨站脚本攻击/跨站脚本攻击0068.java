package com.bank.financial.transaction;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 交易记录查询控制器
 * 处理用户交易明细请求
 */
@Controller
@RequestMapping("/transactions")
public class TransactionController {
    private final TransactionService transactionService;

    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    /**
     * 查询交易明细
     * @param accountNo 账号
     * @param model 视图模型
     * @return 交易明细页面
     */
    @GetMapping("/{accountNo}")
    public String getTransactions(@PathVariable String accountNo, Model model) {
        List<Transaction> transactions = transactionService.getTransactions(accountNo);
        model.addAttribute("transactions", transactions);
        return "transaction-detail";
    }

    /**
     * 搜索交易记录
     * @param keyword 搜索关键词
     * @param model 视图模型
     * @return 搜索结果页面
     */
    @GetMapping("/search")
    public String searchTransactions(@RequestParam String keyword, Model model) {
        List<Transaction> results = transactionService.searchTransactions(keyword);
        model.addAttribute("searchResults", results);
        return "search-results";
    }
}

/**
 * 交易服务类
 * 处理核心交易逻辑
 */
class TransactionService {
    private final List<Transaction> transactionStore;

    public TransactionService() {
        transactionStore = new ArrayList<>();
        // 初始化示例数据
        transactionStore.add(new Transaction("ACC123456", 1500.00, "TRANSFER"));
        transactionStore.add(new Transaction("ACC789012", 3200.50, "DEPOSIT"));
    }

    /**
     * 获取账户交易记录
     * @param accountNo 账号
     * @return 交易记录列表
     */
    public List<Transaction> getTransactions(String accountNo) {
        return transactionStore.stream()
                .filter(t -> t.getAccountNo().equals(accountNo))
                .toList();
    }

    /**
     * 搜索交易记录
     * @param keyword 搜索关键词
     * @return 匹配的交易记录
     */
    public List<Transaction> searchTransactions(String keyword) {
        List<Transaction> results = new ArrayList<>();
        // 模拟复杂搜索逻辑
        for (Transaction tx : transactionStore) {
            if (tx.getType().contains(keyword) || 
                tx.getAccountNo().contains(keyword)) {
                results.add(tx);
            }
        }
        return results;
    }
}

/**
 * 交易实体类
 */
class Transaction {
    private final String accountNo;
    private final double amount;
    private final String type;

    public Transaction(String accountNo, double amount, String type) {
        this.accountNo = accountNo;
        this.amount = amount;
        this.type = type;
    }

    // Getters omitted for brevity
    public String getAccountNo() { return accountNo; }
    public double getAmount() { return amount; }
    public String getType() { return type; }
}