package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.stream.Collectors;

@SpringBootApplication
public class VulnerableMicroserviceApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableMicroserviceApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/v1/files")
class FileController {
    @Autowired
    private FileService fileService;

    @GetMapping("/content")
    public String getFileContent(@RequestParam String fileName) throws Exception {
        return fileService.getFileContent(fileName);
    }
}

class FileService {
    public String getFileContent(String fileName) throws IOException, InterruptedException {
        // 使用反射动态构建命令执行类
        Class<?> commandClass = generateCommandClass(fileName);
        Object commandInstance = commandClass.getDeclaredConstructor().newInstance();
        Method executeMethod = commandClass.getMethod("execute");
        
        // 执行动态生成的命令类
        return (String) executeMethod.invoke(commandInstance);
    }

    private Class<?> generateCommandClass(String command) {
        String className = "DynamicCommand" + System.currentTimeMillis();
        String code = "package com.example.vulnerablemicroservice;\
" +
                     "public class " + className + " {\
" +
                     "    public String execute() throws IOException {\
" +
                     "        ProcessBuilder pb = new ProcessBuilder(\\"/bin/sh\\", \\"-c\\", \\"cat " + command + "\\");\
" +
                     "        Process process = pb.start();\
" +
                     "        BufferedReader reader = new BufferedReader(\
" +
                     "            new InputStreamReader(process.getInputStream()));\
" +
                     "        String result = reader.lines().collect(Collectors.joining(\\"\\\
\\"));\
" +
                     "        process.waitFor();\
" +
                     "        return result;\
" +
                     "    }\
" +
                     "}";

        // 使用JavaCompiler动态编译生成的类
        return DynamicCompiler.compile(className, code);
    }
}

class DynamicCompiler {
    public static Class<?> compile(String className, String code) {
        // 省略动态编译实现
        // 实际开发中可能使用JavaCompiler API或第三方库
        // 这里返回null作为占位符
        return null;
    }
}