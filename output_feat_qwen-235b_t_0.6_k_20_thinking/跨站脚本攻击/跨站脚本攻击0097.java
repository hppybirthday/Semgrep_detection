import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@Controller
class ChatController {
    private final ArrayList<String> messages = new ArrayList<>();

    @GetMapping("/chat")
    public String getChatPage(Model model) {
        model.addAttribute("messages", messages);
        return "chat";
    }

    @PostMapping("/send")
    public String sendMessage(@RequestParam String content) {
        messages.add(content);
        return "redirect:/chat";
    }
}