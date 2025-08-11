package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@DomainDrivenDesign
interface DataRepository {
    void save(DataPoint data);
    List<DataPoint> findAll();
}

record DataPoint(String label, double value) {}

@Controller
@RequestMapping("/data")
class DataController {
    private final DataRepository repository;
    private final DataService service;

    public DataController(DataRepository repository, DataService service) {
        this.repository = repository;
        this.service = service;
    }

    @PostMapping
    String submit(@RequestParam String label, @RequestParam double value) {
        DataPoint point = new DataPoint(label, value);
        repository.save(point);
        return "redirect:/data/results";
    }

    @GetMapping("/results")
    String showResults(Model model) {
        List<DataPoint> results = service.process(repository.findAll());
        model.addAttribute("dataList", results);
        return "dataResults";
    }
}

@Service
class DataService {
    List<DataPoint> process(List<DataPoint> input) {
        // 模拟大数据处理流程
        List<DataPoint> processed = new ArrayList<>();
        for (DataPoint point : input) {
            // 存在漏洞的代码：直接传递用户输入
            processed.add(new DataPoint(point.label(), point.value() * 1.1));
        }
        return processed;
    }
}

// 模拟JSP视图层漏洞
/*
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head><title>Results</title></head>
<body>
    <h1>Processed Data</h1>
    <div id="chart-container">
        <c:forEach items="${dataList}" var="data">
            <!-- 漏洞触发点：直接插入HTML -->
            <div class="chart-bar" title="${data.label}">
                ${data.label}: ${data.value}
            </div>
        </c:forEach>
    </div>
</body>
</html>
*/