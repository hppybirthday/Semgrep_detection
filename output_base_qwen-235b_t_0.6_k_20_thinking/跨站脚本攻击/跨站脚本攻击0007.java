import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class GameChatSystem extends JFrame {
    private JEditorPane chatDisplay;
    private JTextField inputField;
    private Player currentPlayer;

    public GameChatSystem() {
        initializeUI();
        currentPlayer = new Player("Guest");
    }

    private void initializeUI() {
        setTitle("Game Chat System");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        
        chatDisplay = new JEditorPane();
        chatDisplay.setContentType("text/html");
        chatDisplay.setEditable(false);
        
        inputField = new JTextField();
        JButton sendButton = new JButton("Send");
        
        sendButton.addActionListener(e -> processMessage());
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(inputField, BorderLayout.CENTER);
        panel.add(sendButton, BorderLayout.EAST);
        
        add(new JScrollPane(chatDisplay), BorderLayout.CENTER);
        add(panel, BorderLayout.SOUTH);
    }

    private void processMessage() {
        String rawMessage = inputField.getText();
        if (rawMessage.isEmpty()) return;
        
        // Vulnerable: Directly concatenating user input into HTML
        String htmlMessage = "<div style='margin:5px;border-left:3px solid #666;padding-left:10px;'>" +
                           "<b>" + currentPlayer.getName() + "</b>: " + rawMessage + "</div>";
        
        chatDisplay.setText(chatDisplay.getText() + htmlMessage);
        inputField.setText("");
    }

    static class Player {
        private String name;
        
        Player(String name) {
            this.name = name;
        }
        
        String getName() {
            return name;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new GameChatSystem().setVisible(true);
        });
    }
}