import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// 领域模型
class Account {
    private String accountId;
    
    public Account(String accountId) {
        this.accountId = accountId;
    }
    
    public String getAccountId() {
        return accountId;
    }
}

// 基础设施服务
interface ExternalCommandService {
    String executeCommand(String command) throws IOException;
}

class LinuxCommandService implements ExternalCommandService {
    @Override
    public String executeCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec("/bin/bash -c " + command);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

// 领域服务
class ReportService {
    private ExternalCommandService commandService;
    
    public ReportService(ExternalCommandService commandService) {
        this.commandService = commandService;
    }
    
    public String generateAccountReport(String accountId) throws IOException {
        // 漏洞点：直接拼接用户输入到系统命令
        String command = "generate_report.sh -a " + accountId + " | grep -v 'confidential'";
        return commandService.executeCommand(command);
    }
}

// 应用服务
class ReportingApplicationService {
    private ReportService reportService;
    
    public ReportingApplicationService(ReportService reportService) {
        this.reportService = reportService;
    }
    
    public String handleReportRequest(String accountId) throws IOException {
        return reportService.generateAccountReport(accountId);
    }
}

// 模拟存储库
class AccountRepository {
    public Account findAccount(String accountId) {
        // 简化实现
        return new Account(accountId);
    }
}

// 主程序
public class BankingSystem {
    public static void main(String[] args) {
        try {
            ExternalCommandService commandService = new LinuxCommandService();
            ReportService reportService = new ReportService(commandService);
            ReportingApplicationService appService = new ReportingApplicationService(reportService);
            
            // 模拟用户输入
            String userInput = args.length > 0 ? args[0] : "12345";
            System.out.println("执行结果：\
" + appService.handleReportRequest(userInput));
        } catch (Exception e) {
            System.err.println("错误：" + e.getMessage());
        }
    }
}