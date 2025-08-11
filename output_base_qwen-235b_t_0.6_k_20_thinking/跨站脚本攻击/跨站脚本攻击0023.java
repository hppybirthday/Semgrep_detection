import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class Game extends JFrame {
    private JTextArea chatDisplay;
    private JTextField inputField;
    private ChatSystem chatSystem;

    public Game() {
        chatSystem = new ChatSystem();
        initializeUI();
    }

    private void initializeUI() {
        setTitle("XSS Game Chat");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        chatDisplay = new JTextArea();
        chatDisplay.setEditable(false);
        add(new JScrollPane(chatDisplay), BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputField = new JTextField();
        JButton sendButton = new JButton("Send");

        sendButton.addActionListener(e -> sendMessage());
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        add(inputPanel, BorderLayout.SOUTH);
    }

    private void sendMessage() {
        String message = inputField.getText();
        if (!message.isEmpty()) {
            chatSystem.addMessage(message);
            updateChatDisplay();
            inputField.setText("");
        }
    }

    private void updateChatDisplay() {
        chatDisplay.setText(chatSystem.getFormattedMessages());
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new Game().setVisible(true);
        });
    }
}

class ChatSystem {
    private StringBuilder messages = new StringBuilder();

    public void addMessage(String message) {
        // Vulnerable: Directly appending raw user input to HTML content
        messages.append("<div>").append(message).append("</div>\
");
    }

    public String getFormattedMessages() {
        return "<html><body style='font-family: Arial;'>" + messages.toString() + "</body></html>";
    }
}