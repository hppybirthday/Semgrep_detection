package com.example.scheduler.job;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

@JobHandler("pdfReportJob")
@Component
public class PdfReportJobHandler extends IJobHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(PdfReportJobHandler.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        try {
            Map<String, String> params = parseJobParameters(param);
            String reportPath = params.get("reportPath");
            String sanitizedPath = sanitizeInput(reportPath);
            ProcessBuilder builder = constructCommand(sanitizedPath);
            
            Process process = builder.start();
            String output = readProcessOutput(process.getInputStream());
            
            int exitCode = process.waitFor();
            return exitCode == 0 ? SUCCESS(output) : new ReturnT<>(FAIL.getCode(), "Command failed with exit code " + exitCode);
            
        } catch (Exception e) {
            LOGGER.error("Job execution failed", e);
            return FAIL;
        }
    }

    private Map<String, String> parseJobParameters(String param) throws IOException {
        // 将JSON参数解析为键值对
        return MAPPER.readValue(param, new TypeReference<>() {});
    }

    private String sanitizeInput(String input) {
        // 限制路径长度并移除分号
        if (input.length() > 255) {
            throw new IllegalArgumentException("Path exceeds maximum length");
        }
        return input.replace(";", "");
    }

    private ProcessBuilder constructCommand(String path) {
        // 构建Windows平台下的PDF处理命令
        return new ProcessBuilder("cmd.exe", "/c", "magic-pdf -generate " + path);
    }

    private String readProcessOutput(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}