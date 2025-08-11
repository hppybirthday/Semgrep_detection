import java.sql.*;
import java.util.*;
import org.springframework.stereotype.*;
import com.baomidou.mybatisplus.core.conditions.query.*;
import com.baomidou.mybatisplus.extension.plugins.pagination.*;

@Service
public class ChatService {
    
    private final ChatMessageMapper chatMessageMapper;

    public ChatService(ChatMessageMapper chatMessageMapper) {
        this.chatMessageMapper = chatMessageMapper;
    }

    public Page<ChatMessage> searchMessages(String keyword, int pageNum, int pageSize, String sortBy, String sortOrder) {
        Page<ChatMessage> page = new Page<>(pageNum, pageSize);
        // 漏洞点：直接拼接ORDER BY子句
        String orderByClause = "";
        if (sortBy != null && !sortBy.isEmpty()) {
            orderByClause = "ORDER BY " + sortBy;
            if (sortOrder != null && !sortOrder.isEmpty()) {
                orderByClause += " " + sortOrder;
            }
        }
        
        // 使用MyBatis-Plus原生分页查询
        return chatMessageMapper.selectPage(page, new QueryWrapper<ChatMessage>().like("content", keyword).orderByRaw(orderByClause));
    }
}

@Mapper
public interface ChatMessageMapper extends BaseMapper<ChatMessage> {}

public class ChatMessage {
    private Long id;
    private String content;
    private String username;
    private LocalDateTime timestamp;
    // 省略getter/setter
}

@RestController
@RequestMapping("/chat")
public class ChatController {
    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping("/search")
    public ResponseEntity<Page<ChatMessage>> searchMessages(
        @RequestParam String keyword,
        @RequestParam int pageNum,
        @RequestParam int pageSize,
        @RequestParam(required = false) String sortBy,
        @RequestParam(required = false) String sortOrder) {
        
        return ResponseEntity.ok(chatService.searchMessages(keyword, pageNum, pageSize, sortBy, sortOrder));
    }
}