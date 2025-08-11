package com.example.bigdata.controller;

import com.example.bigdata.service.DataProcessor;
import com.example.bigdata.model.DataModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelAndView;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
@RequestMapping("/process")
public class DataProcessingController {
    
    @Autowired
    private DataProcessor dataProcessor;

    @GetMapping
    public ModelAndView processData(@RequestParam String fieldTitle, HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("dataResult");
        try {
            DataModel result = dataProcessor.generateDataSummary(fieldTitle);
            modelAndView.addObject("summary", result.getSummary());
            modelAndView.addObject("fieldTitle", fieldTitle);
            // 模拟大数据处理耗时
            Thread.sleep(150);
        } catch (Exception e) {
            modelAndView.setViewName("error");
            modelAndView.addObject("errorMsg", "Error processing field: " + fieldTitle);
            modelAndView.addObject("rawUrl", request.getRequestURL().append("?fieldTitle=").append(fieldTitle));
        }
        return modelAndView;
    }
}

package com.example.bigdata.service;

import com.example.bigdata.model.DataModel;
import org.springframework.stereotype.Service;

@Service
public class DataProcessor {
    public DataModel generateDataSummary(String fieldTitle) {
        // 模拟大数据处理逻辑
        String summary = String.format("Processed %d records for field: %s", 
            (int)(Math.random() * 1000000), fieldTitle);
        return new DataModel(summary);
    }
}

package com.example.bigdata.model;

public class DataModel {
    private String summary;

    public DataModel(String summary) {
        this.summary = summary;
    }

    public String getSummary() {
        return summary;
    }
}

// JSP视图 dataResult.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head>
    <title>${fieldTitle}</title>
</head>
<body>
    <h1>${summary}</h1>
    <div id="data-details">
        <!-- 其他处理结果展示 -->
    </div>
</body>
</html>

// error.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head>
    <title>Error</title>
</head>
<body>
    <h2>${errorMsg}</h2>
    <p>Request URL: ${rawUrl}</p>
</body>
</html>