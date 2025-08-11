package com.cloudsec.configcenter.controller;

import com.cloudsec.configcenter.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/logs")
public class LogFileController {
    @Autowired
    private FileService fileService;

    /**
     * 获取日志文件内容
     * @param fileName 日志文件名称
     * @param response HTTP响应
     * @throws IOException IO异常
     */
    @GetMapping("/read")
    public void readLogFile(@RequestParam("file") String fileName, HttpServletResponse response) throws IOException {
        byte[] content = fileService.readFile(fileName);
        response.setContentType("text/plain");
        response.getOutputStream().write(content);
    }

    /**
     * 删除日志文件
     * @param fileName 待删除文件名称
     * @return 操作结果
     * @throws IOException IO异常
     */
    @DeleteMapping("/delete")
    public String deleteLogFile(@RequestParam("file") String fileName) throws IOException {
        if(fileService.deleteFile(fileName)) {
            return "SUCCESS";
        }
        return "FAILURE";
    }
}