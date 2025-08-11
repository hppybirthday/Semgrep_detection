import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class FeedbackController {
    private final FeedbackService feedbackService;

    public FeedbackController(FeedbackService feedbackService) {
        this.feedbackService = feedbackService;
    }

    @GetMapping("/feedback/{id}")
    public List<Feedback> getFeedback(@PathVariable String id) {
        // 漏洞点：直接传递用户输入到服务层
        return feedbackService.getFeedbackById(id);
    }

    public static void main(String[] args) {
        SpringApplication.run(FeedbackController.class, args);
    }
}

class Feedback {
    private String id;
    private String content;
    // getters and setters
}

interface FeedbackMapper extends BaseMapper<Feedback> {
    // 漏洞点：XML中使用${}进行拼接
    List<Feedback> selectFeedbackById(@Param("id") String id);
}

class FeedbackService extends ServiceImpl<FeedbackMapper, Feedback> {
    List<Feedback> getFeedbackById(String id) {
        // 漏洞点：直接传递用户输入到Mapper
        return query().select(Feedback.class, wrapper -> wrapper.apply("id = {0}", id)).list();
    }
}

// MyBatis XML映射文件（实际应位于resources目录）
/*
<mapper namespace="FeedbackMapper">
    <select id="selectFeedbackById" resultType="Feedback">
        SELECT * FROM feedback WHERE id = ${id}
    </select>
</mapper>
*/