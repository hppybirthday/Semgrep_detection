import java.io.*;
import java.util.*;

// 高抽象建模的金融系统组件
interface ReportGenerator {
    void generateAccountReport(String accountId) throws Exception;
}

class AccountReportServiceImpl implements ReportGenerator {
    @Override
    public void generateAccountReport(String accountId) throws Exception {
        // 模拟金融系统中的危险设计：直接拼接系统命令
        String command = "tar -czf /var/reports/account_" + accountId + ".tar.gz /data/accounts/" + accountId;
        
        // 使用ProcessBuilder执行系统命令（漏洞触发点）
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 忽略安全检查的流处理
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[REPORT STATUS] " + line);
        }
        
        int exitCode = process.waitFor();
        System.out.println("报告生成完成，退出代码：" + exitCode);
    }
}

// 模拟银行系统的API控制器
class ReportController {
    private final ReportGenerator reportGenerator;

    public ReportController(ReportGenerator reportGenerator) {
        this.reportGenerator = reportGenerator;
    }

    public void handleGenerateReport(String accountId) {
        try {
            System.out.println("[金融系统日志] 正在为账户 " + accountId + " 生成报告...");
            reportGenerator.generateAccountReport(accountId);
            System.out.println("[金融系统日志] 报告生成成功");
        } catch (Exception e) {
            System.err.println("[ERROR] 报告生成失败: " + e.getMessage());
        }
    }
}

// 模拟金融系统的主入口
public class BankingSystem {
    public static void main(String[] args) {
        // 初始化金融系统组件
        ReportGenerator reportGenerator = new AccountReportServiceImpl();
        ReportController controller = new ReportController(reportGenerator);
        
        // 模拟用户输入（攻击者可能控制输入）
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入账户ID进行报告生成: ");
        String accountId = scanner.nextLine();
        
        // 处理金融业务请求
        controller.handleGenerateReport(accountId);
    }
}