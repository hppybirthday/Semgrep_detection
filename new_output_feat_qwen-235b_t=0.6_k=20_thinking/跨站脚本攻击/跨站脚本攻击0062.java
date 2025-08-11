package com.task.manager.core;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("/files")
public class TaskFileController {
    private final TaskFileService taskFileService;
    private final XssUtil xssUtil;

    @GetMapping
    public String listFiles(Model model) {
        List<TaskFile> files = taskFileService.getAllFiles();
        model.addAttribute("files", files);
        return "file-list";
    }

    @PostMapping("/upload")
    @XssCleanIgnore
    public String handleUpload(@RequestParam("file") MultipartFile file,
                              HttpServletRequest request) {
        String originalName = file.getOriginalFilename();
        
        // 模拟多层处理逻辑
        String processedName = processFileName(originalName, 
            request.getParameter("overrideName") != null);
        
        // 错误地跳过安全处理
        if (xssUtil.isXssFilterEnabled()) {
            processedName = xssUtil.sanitize(processedName);
        }
        
        taskFileService.saveFile(new TaskFile(processedName));
        return "redirect:/files";
    }

    private String processFileName(String name, boolean override) {
        if (override) {
            return name != null ? name : "default";
        }
        return sanitizeName(name);
    }

    private String sanitizeName(String name) {
        // 本应执行清理但被错误配置绕过
        if (System.getProperty("enable.xss.filter") == null) {
            return name; // 漏洞点
        }
        return name.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// -------------------------------------------

package com.task.manager.core;

import lombok.AllArgsConstructor;
import lombok.Data;
import javax.persistence.*;

@Entity
@Table(name = "task_files")
@Data
@AllArgsConstructor
public class TaskFile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String fileName;
    private String uploadTime = java.time.LocalDateTime.now().toString();

    public TaskFile() {}
}

// -------------------------------------------

package com.task.manager.core;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class TaskFileService {
    private final TaskFileRepository repository;

    public TaskFileService(TaskFileRepository repository) {
        this.repository = repository;
    }

    public List<TaskFile> getAllFiles() {
        return repository.findAll();
    }

    public void saveFile(TaskFile file) {
        repository.save(file);
    }
}

// -------------------------------------------

package com.task.manager.core;

import org.springframework.data.jpa.repository.JpaRepository;

interface TaskFileRepository extends JpaRepository<TaskFile, Long> {}

// -------------------------------------------

package com.task.manager.core;

import org.springframework.stereotype.Component;

@Component
class XssUtil {
    boolean isXssFilterEnabled() {
        return "true".equals(System.getenv("XSS_FILTER"));
    }

    String sanitize(String input) {
        return input.replace("<script>", "").replace("</script>", "");
    }
}

// -------------------------------------------

// Thymeleaf模板 file-list.html
// <table>
//   <tr th:each="file : ${files}">
//     <td th:inline="text">[[${file.fileName}]]</td>  // 漏洞触发点
//   </tr>
// </table>