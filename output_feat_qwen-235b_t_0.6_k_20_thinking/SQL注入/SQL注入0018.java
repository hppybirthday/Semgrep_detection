import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/chat")
public class ChatController {
    @Autowired
    private ChatService chatService;

    @DeleteMapping("/delete")
    public String deleteMessages(@RequestParam String ids) {
        return chatService.deleteMessages(ids) ? "Success" : "Failed";
    }
}

@Service
class ChatService {
    @Autowired
    private ChatMapper chatMapper;

    public boolean deleteMessages(String ids) {
        try {
            chatMapper.deleteMessages(ids);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

@Mapper
interface ChatMapper {
    @Select("DELETE FROM chat_messages WHERE id IN (${ids})")
    void deleteMessages(String ids);
}

// MyBatis XML Mapping (equivalent form):
// <delete id="deleteMessages">
//     DELETE FROM chat_messages WHERE id IN (${ids})
// </delete>

/*
CREATE TABLE chat_messages (
    id INT PRIMARY KEY,
    content TEXT,
    user_id INT
);
*/