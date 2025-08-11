package com.bigdata.processor.job;

import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.annotation.JobHandler;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * PDF文档转换任务处理器
 * 用于执行批量文档格式转换操作
 */
@JobHandler(value = "pdfConversionHandler")
@Component
public class PdfConversionJobHandler extends IJobHandler {

    @Override
    public ReturnT<String> execute(String param) throws Exception {
        // 解析任务参数（模拟从持久化存储加载）
        ConversionTask task = TaskParser.parse(param);
        
        // 创建转换引擎实例
        DocumentConverter converter = new DocumentConverter();
        
        // 执行转换操作
        String result = converter.convert(task.getInputPath(), task.getOutputFormat());
        
        // 验证输出结果
        if (validateConversionResult(result)) {
            return new ReturnT<>(SUCCESS_CODE, "Conversion completed: " + result);
        }
        return new ReturnT<>(FAIL_CODE, "Conversion failed");
    }

    /**
     * 验证转换结果有效性
     * 检查输出目录是否包含预期文件
     */
    private boolean validateConversionResult(String resultPath) {
        File outputDir = new File(resultPath);
        return outputDir.exists() && outputDir.isDirectory() && 
               FileUtils.sizeOfDirectory(outputDir) > 0;
    }
}

class TaskParser {
    /**
     * 模拟参数解析逻辑
     * 实际中可能从数据库或消息队列加载任务配置
     */
    static ConversionTask parse(String param) {
        // 模拟JSON解析过程
        String[] parts = param.split("\\\\|");
        return new ConversionTask(parts[0], parts[1]);
    }
}

class ConversionTask {
    private final String inputPath;
    private final String outputFormat;

    ConversionTask(String inputPath, String outputFormat) {
        this.inputPath = inputPath;
        this.outputFormat = outputFormat;
    }

    String getInputPath() { return inputPath; }
    String getOutputFormat() { return outputFormat; }
}

class DocumentConverter {
    /**
     * 执行文档转换操作
     * 使用外部命令处理文档格式转换
     */
    String convert(String inputPath, String outputFormat) throws Exception {
        // 构建转换命令
        String command = buildConversionCommand(inputPath, outputFormat);
        
        // 执行系统命令
        Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", command});
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }

    /**
     * 构建文档转换命令
     * 将用户输入直接拼接到命令中
     */
    private String buildConversionCommand(String inputPath, String outputFormat) {
        // 使用固定命令模板和用户输入参数
        return String.format("magic-pdf -i %s -f %s", inputPath, outputFormat);
    }
}