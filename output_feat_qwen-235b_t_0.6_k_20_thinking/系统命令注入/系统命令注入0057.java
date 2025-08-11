package com.bigdata.job;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class JobExecutionService {
    @Autowired
    private CommandExecutor commandExecutor;

    public void processJobRequest(HttpServletRequest request) {
        String scriptPath = request.getParameter("script");
        String inputPath = request.getParameter("input");
        String outputPath = request.getParameter("output");
        
        // 构建大数据处理命令
        String command = String.format("hadoop jar /opt/bigdata/processor.jar \\
            -Dmapreduce.job.queuename=%s \\
            -input %s -output %s -script %s",
            request.getParameter("queue"),
            inputPath, outputPath, scriptPath);

        commandExecutor.execute(command);
    }
}

class CommandExecutor {
    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    void execute(String command) {
        executor.submit(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", command);
                Process process = pb.start();
                int exitCode = process.waitFor();
                
                if (exitCode != 0) {
                    System.err.println("Command failed: " + command);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}

// 模拟Tomcat过滤器层
public class JobFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // 作业脚本执行入口
        if (httpRequest.getRequestURI().contains("/executeJob")) {
            JobExecutionService service = new JobExecutionService();
            service.processJobRequest(httpRequest);
        }
        
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}
}