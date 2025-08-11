package com.example.scheduler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import javax.annotation.PostConstruct;
import org.slf4j.*;

@RestController
@RequestMapping("/task")
public class ScheduleController {
    private static final Logger logger = LoggerFactory.getLogger(ScheduleController.class);
    private final ScheduleService scheduleService;

    public ScheduleController(ScheduleService scheduleService) {
        this.scheduleService = scheduleService;
    }

    @GetMapping("/exec")
    public String executeJob(@RequestParam String s) {
        try {
            return scheduleService.runScheduledJob(s);
        } catch (Exception e) {
            logger.error("Job execution failed", e);
            return "Error: " + e.getMessage();
        }
    }
}

class ScheduleService {
    private final JobHandler jobHandler;

    public ScheduleService() {
        this.jobHandler = new JobHandler();
    }

    String runScheduledJob(String param) throws Exception {
        validateParam(param);
        return jobHandler.processJob(param);
    }

    private void validateParam(String param) {
        // 校验参数为正整数（业务规则）
        if (!param.matches("\\\\d+")) {
            throw new IllegalArgumentException("Invalid parameter format");
        }
    }
}

class JobHandler {
    private final CommandExecutor executor;

    public JobHandler() {
        this.executor = new CommandExecutor();
    }

    String processJob(String param) throws Exception {
        List<String> commands = new ArrayList<>();
        commands.add("sh");
        commands.add("-c");
        commands.add("echo \\"Processing job ID: " + param + "\\" && date");
        
        // 构造带参数的命令（业务需求）
        String dynamicParam = getDynamicParam(param);
        commands.add("| grep " + dynamicParam);
        
        return executor.execute(commands);
    }

    private String getDynamicParam(String base) {
        // 模拟参数增强处理（业务逻辑）
        return base + "_suffix";
    }
}

class CommandExecutor {
    String execute(List<String> commands) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(commands);
        Process process = pb.start();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        }
    }
}