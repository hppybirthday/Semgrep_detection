import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.apache.ibatis.annotations.*;
import org.apache.ibatis.builder.SqlSourceBuilder;
import org.apache.ibatis.mapping.SqlSource;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.scripting.xmltags.XMLLanguageDriver;

@RestController
@RequestMapping("/chat")
public class ChatController {
    private final ChatService chatService;

    @Autowired
    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping("/messages")
    public List<Message> getMessages(@RequestParam String userId,
                                    @RequestParam(required = false) String sort,
                                    @RequestParam(required = false) String order) {
        return chatService.searchMessages(userId, sort, order);
    }
}

class ChatService {
    private final MessageMapper messageMapper;

    public ChatService(MessageMapper messageMapper) {
        this.messageMapper = messageMapper;
    }

    public List<Message> searchMessages(String userId, String sort, String order) {
        return Optional.ofNullable(messageMapper.searchMessages(userId, sort, order))
                      .orElse(Collections.emptyList());
    }
}

@Mapper
interface MessageMapper {
    @SelectProvider(type = SqlProvider.class, method = "buildQuery")
    List<Message> searchMessages(@Param("userId") String userId,
                                @Param("sort") String sort,
                                @Param("order") String order);
}

class SqlProvider {
    static String buildQuery(Map<String, Object> params) {
        String base = "SELECT * FROM messages WHERE user_id = '" + params.get("userId") + "'";
        String orderBy = "";
        
        if (params.get("sort") != null && params.get("order") != null) {
            // 错误的转义实现
            String safeOrder = SqlUtil.escapeOrderBySql((String)params.get("order"));
            orderBy = " ORDER BY " + params.get("sort") + " " + safeOrder;
        }
        
        return base + orderBy;
    }
}

class SqlUtil {
    // 模拟不完整的转义方法
    static String escapeOrderBySql(String input) {
        return input.replaceAll("[;\\\\\\\\'"]", ""); // 仅移除部分特殊字符
    }
}

class Message {
    private String content;
    private String sender;
    
    // Getters and setters
}

// 模拟MyBatis配置
@Configuration
class MyBatisConfig {
    @Bean
    public XMLLanguageDriver xmlLanguageDriver() {
        return new XMLLanguageDriver();
    }
}