package com.bank.core;

import java.io.*;
import java.util.*;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * @Description: 银行交易日志处理器
 * @Author: security-team
 */
public class TransactionLogger {
    private static final Logger logger = LogManager.getLogger(TransactionLogger.class);
    private final CommandExecutor commandExecutor;

    public TransactionLogger(CommandExecutor executor) {
        this.commandExecutor = executor;
    }

    public boolean logTransaction(String accountId, double amount) {
        try {
            String result = commandExecutor.execute(
                new String[]{"/bin/bash", "-c", 
                String.format("/opt/bank/scripts/log_transaction.sh %s %.2f", accountId, amount)
            }
            );
            logger.info("交易日志记录成功: {}", result);
            return true;
        } catch (Exception e) {
            logger.error("交易日志记录失败: {}", e.getMessage());
            return false;
        }
    }
}

class SystemCommandExecutor implements CommandExecutor {
    @Override
    public String execute(String[] command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("命令执行失败，退出码: " + exitCode);
            }
            
            return output.toString();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("命令执行被中断", e);
        }
    }
}

interface CommandExecutor {
    String execute(String[] command) throws IOException;
}

// 模拟银行服务层
package com.bank.service;

import com.bank.core.*;
import java.util.*;

public class BankingService {
    private final TransactionLogger transactionLogger;

    public BankingService() {
        this.transactionLogger = new TransactionLogger(new SystemCommandExecutor());
    }

    public boolean processTransfer(String fromAccount, String toAccount, double amount) {
        // 模拟交易处理逻辑
        if (validateAccounts(fromAccount, toAccount) && amount > 0) {
            boolean success = performTransfer(fromAccount, toAccount, amount);
            if (success) {
                // 记录交易日志（存在命令注入漏洞）
                return transactionLogger.logTransaction(fromAccount, amount);
            }
        }
        return false;
    }

    private boolean validateAccounts(String... accounts) {
        // 模拟账户验证逻辑
        return Arrays.stream(accounts).allMatch(acc -> acc.matches("\\\\d{10}"));
    }

    private boolean performTransfer(String from, String to, double amount) {
        // 模拟转账操作
        return new Random().nextBoolean(); // 50%成功率模拟
    }
}

// 模拟控制器层
package com.bank.controller;

import com.bank.service.*;
import java.util.Scanner;

public class BankingController {
    private final BankingService bankingService = new BankingService();

    public static void main(String[] args) {
        BankingController controller = new BankingController();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("欢迎使用银行转账系统");
        System.out.print("请输入转出账户: ");
        String fromAccount = scanner.nextLine();
        
        System.out.print("请输入转入账户: ");
        String toAccount = scanner.nextLine();
        
        System.out.print("请输入转账金额: ");
        try {
            double amount = Double.parseDouble(scanner.nextLine());
            
            if (controller.processTransfer(fromAccount, toAccount, amount)) {
                System.out.println("转账成功!");
            } else {
                System.out.println("转账失败");
            }
        } catch (NumberFormatException e) {
            System.out.println("请输入有效的金额");
        }
    }

    boolean processTransfer(String fromAccount, String toAccount, double amount) {
        return bankingService.processTransfer(fromAccount, toAccount, amount);
    }
}