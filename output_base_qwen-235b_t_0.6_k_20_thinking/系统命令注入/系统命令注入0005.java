package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
class CommandInjectionController {
    
    @GetMapping("/backup")
    public String backupFile(@RequestParam String filename) {
        try {
            // 元编程特性：通过反射动态获取Runtime类
            Class<?> rtClass = Class.forName("java.lang.Runtime");
            Object rtInstance = rtClass.getMethod("getRuntime").invoke(null);
            
            // 漏洞点：用户输入直接拼接进系统命令
            String rawCommand = String.format("tar -cf %s.tar %s", filename, filename);
            String[] cmdArray = rawCommand.split(" ");
            
            // 动态调用exec方法执行命令
            Method execMethod = rtClass.getMethod("exec", String[].class);
            Process process = (Process) execMethod.invoke(rtInstance, new Object[]{cmdArray});
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder("Backup result:\
");
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
            
        } catch (Exception e) {
            return String.format("Error: %%s\
StackTrace: %%s", 
                e.getMessage(), Arrays.toString(e.getStackTrace()));
        }
    }
}
