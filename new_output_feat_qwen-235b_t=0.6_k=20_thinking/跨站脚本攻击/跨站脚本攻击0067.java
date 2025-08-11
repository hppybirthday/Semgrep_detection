package com.example.app;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@Controller
@RequestMapping("/post")
public class PostController {
    private final PostService postService = new PostService();
    private final ErrorService errorService = new ErrorService();

    @PostMapping("/submit")
    @ResponseBody
    public String handlePostSubmission(@RequestParam String title) {
        try {
            postService.validateTitle(title);
            return "<div>Post submitted successfully</div>";
        } catch (ValidationException e) {
            return errorService.buildErrorMessage(e.getInput(), e.getMessage());
        }
    }
}

class PostService {
    private static final int MAX_LENGTH = 50;

    void validateTitle(String title) throws ValidationException {
        if (title == null || title.isEmpty()) {
            throw new ValidationException(title, "Title cannot be empty");
        }
        
        if (title.length() > MAX_LENGTH) {
            // Simulate partial sanitization that doesn't prevent XSS
            String sanitized = HtmlUtils.sanitize(title);
            if (sanitized.length() > MAX_LENGTH) {
                throw new ValidationException(title, "Title too long");
            }
        }
        
        // Additional validation steps...
    }
}

class ValidationException extends Exception {
    private final String input;

    ValidationException(String input, String message) {
        super(message);
        this.input = input;
    }

    String getInput() {
        return input;
    }
}

class ErrorService {
    String buildErrorMessage(String input, String message) {
        // Vulnerable string concatenation in error message
        return "<div class='error'>" + message + ": " + input + "</div>";
    }
}

class HtmlUtils {
    // Seems security-conscious but not used where it matters
    static String sanitize(String input) {
        if (input == null) return "";
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }

    // Additional utility methods that aren't used in the vulnerable path
    static String escapeJs(String input) {
        if (input == null) return "";
        return input.replace("\\\\"", "\\\\\\""");
    }
}