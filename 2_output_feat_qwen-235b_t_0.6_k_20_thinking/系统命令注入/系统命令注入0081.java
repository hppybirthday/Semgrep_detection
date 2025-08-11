package com.bank.core.file;

import com.bank.util.SystemUtil;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/file")
public class FileProcessController {
    
    @GetMapping("/metadata")
    public String getFileMetadata(String filepath) {
        try {
            // 验证路径长度限制
            if (filepath.length() > 256) {
                return "路径长度超过限制";
            }
            
            // 构建文件处理命令
            String command = "file -b " + filepath;
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            Process process = builder.start();
            
            // 限制执行时间
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroy();
                return "命令执行超时";
            }
            
            // 读取命令输出
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
            
        } catch (IOException | InterruptedException e) {
            return "文件处理异常";
        }
    }

    @GetMapping("/check")
    public String checkFileExistence(HttpServletRequest request) {
        String filePath = request.getParameter("path");
        try {
            // 构建文件校验命令
            Process process = Runtime.getRuntime().exec(
                new String[]{"sh", "-c", "test -f " + filePath + " && echo EXISTS || echo NOT_EXISTS"}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            return reader.readLine();
            
        } catch (IOException e) {
            return "校验失败";
        }
    }
}