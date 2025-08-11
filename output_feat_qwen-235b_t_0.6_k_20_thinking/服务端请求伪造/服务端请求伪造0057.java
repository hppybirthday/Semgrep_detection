package com.bigdata.joblog.infrastructure;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class LogFetcher {
    public String fetchLog(String logUrl) throws IOException {
        URL url = new URL(logUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }
}

package com.bigdata.joblog.application;

import com.bigdata.joblog.domain.JobLog;
import com.bigdata.joblog.domain.JobLogRepository;
import com.bigdata.joblog.infrastructure.LogFetcher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class JobLogService {
    private final JobLogRepository jobLogRepository;
    private final LogFetcher logFetcher;

    public JobLogService(JobLogRepository jobLogRepository, LogFetcher logFetcher) {
        this.jobLogRepository = jobLogRepository;
        this.logFetcher = logFetcher;
    }

    public String getLogDetails(String logId, String src, String srcB) throws IOException {
        // 模拟从JSON配置文件读取参数
        ObjectMapper mapper = new ObjectMapper();
        String jsonConfig = String.format("{\\"src\\":\\"%s\\",\\"srcB\\":\\"%s\\"}", src, srcB);
        JsonNode config = mapper.readTree(jsonConfig);
        
        // 危险地直接拼接URL参数
        String logUrl = String.format("%s?token=%s", 
            config.get("src").asText(), 
            jobLogRepository.getToken(logId)
        );
        
        // SSRF漏洞点：未验证logUrl安全性
        String logContent = logFetcher.fetchLog(logUrl);
        
        // 同时处理第二个参数srcB
        if (!config.get("srcB").isNull()) {
            String auxContent = logFetcher.fetchLog(config.get("srcB").asText());
            logContent += "\
" + auxContent;
        }
        
        return logContent;
    }

    public void killJobLog(String logId, String src) throws IOException {
        // 更危险的场景：直接使用src参数
        String killUrl = String.format("%s?action=kill&logId=%s", src, logId);
        logFetcher.fetchLog(killUrl);
        jobLogRepository.deleteLog(logId);
    }
}

package com.bigdata.joblog.controller;

import com.bigdata.joblog.application.JobLogService;
import com.bigdata.joblog.domain.JobLogRepository;
import com.bigdata.joblog.infrastructure.LogFetcher;
import com.bigdata.joblog.domain.InMemoryJobLogRepository;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JobLogController extends HttpServlet {
    private final JobLogService jobLogService;

    public JobLogController() {
        JobLogRepository repository = new InMemoryJobLogRepository();
        LogFetcher fetcher = new LogFetcher();
        this.jobLogService = new JobLogService(repository, fetcher);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo();
        
        if (path.startsWith("/logDetailCat")) {
            String logId = req.getParameter("id");
            String src = req.getParameter("src");
            String srcB = req.getParameter("srcB");
            
            try {
                String result = jobLogService.getLogDetails(logId, src, srcB);
                resp.getWriter().write(result);
            } catch (Exception e) {
                resp.sendError(500, "Log fetch failed");
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo();
        
        if (path.startsWith("/logKill")) {
            String logId = req.getParameter("id");
            String src = req.getParameter("src");
            
            try {
                jobLogService.killJobLog(logId, src);
                resp.getWriter().write("Job killed successfully");
            } catch (Exception e) {
                resp.sendError(500, "Kill failed");
            }
        }
    }
}