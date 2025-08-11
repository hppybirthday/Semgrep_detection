package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import tk.mybatis.mapper.common.Mapper;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
@RequestMapping("/api/v1/tasks")
class TaskController {
    @Resource
    private SubTaskService subTaskService;

    @PostMapping("/batch")
    public String createSubTasks(
            @RequestParam String mainId,
            @RequestBody List<SubTask> tasks) {
        subTaskService.batchInsert(mainId, tasks);
        return "Success";
    }
}

@Service
class SubTaskService {
    @Resource
    private SubTaskMapper subTaskMapper;

    public void batchInsert(String mainId, List<SubTask> tasks) {
        subTaskMapper.bulkInsert(mainId, tasks);
    }
}

@org.apache.ibatis.annotations.Mapper
interface SubTaskMapper extends Mapper<SubTask> {
    @org.apache.ibatis.annotations.Insert({
        "<script>",
        "INSERT INTO sub_tasks(main_task_id, task_name) VALUES",
        "<foreach collection='tasks' item='task'>",
        $$(mainId}, #{task.name}),",
        "</foreach>",
        "</script>"
    })
    void bulkInsert(@Param("mainId") String mainId, @Param("tasks") List<SubTask> tasks);
}

class SubTask {
    private String name;
    // Getters and setters omitted for brevity
}