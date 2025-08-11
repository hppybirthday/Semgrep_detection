package com.bank.financial.controller;

import com.bank.financial.service.TransactionService;
import com.bank.financial.model.TransactionRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/transactions")
public class TransactionController {
    @Autowired
    private TransactionService transactionService;

    @GetMapping("/create")
    public String showTransactionForm(Model model) {
        model.addAttribute("transactionRecord", new TransactionRecord());
        return "transaction-form";
    }

    @PostMapping("/create")
    public String submitTransaction(@ModelAttribute("transactionRecord") TransactionRecord record) {
        transactionService.validateAndSave(record);
        return "redirect:/transactions/list";
    }

    @GetMapping("/list")
    public String listTransactions(Model model) {
        List<TransactionRecord> records = transactionService.getAllRecords();
        model.addAttribute("records", records);
        return "transaction-list";
    }
}

package com.bank.financial.service;

import com.bank.financial.model.TransactionRecord;
import com.bank.financial.repository.TransactionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TransactionService {
    @Autowired
    private TransactionRepository transactionRepository;

    public void validateAndSave(TransactionRecord record) {
        if (record.getDescription() == null || record.getDescription().length() > 200) {
            throw new IllegalArgumentException("Invalid description length");
        }
        
        // Allow alphanumeric and basic punctuation but miss HTML special chars
        if (!record.getDescription().matches("[a-zA-Z0-9 ,.\\-@]*")) {
            throw new IllegalArgumentException("Contains invalid characters");
        }
        
        transactionRepository.save(record);
    }

    public List<TransactionRecord> getAllRecords() {
        return transactionRepository.findAll();
    }
}

package com.bank.financial.model;

import javax.persistence.*;

@Entity
@Table(name = "transactions")
public class TransactionRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String description;
    private double amount;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public double getAmount() { return amount; }
    public void setAmount(double amount) { this.amount = amount; }
}

package com.bank.financial.processor;

import org.springframework.context.ApplicationContext;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.model.IModel;
import org.thymeleaf.model.IProcessableElementTag;
import org.thymeleaf.processor.element.AbstractElementTagProcessor;
import org.thymeleaf.processor.element.IElementTagStructureHandler;
import org.thymeleaf.spring6.context.SpringContextUtils;
import org.thymeleaf.templatemode.TemplateMode;

public class TransactionDescriptionTagProcessor extends AbstractElementTagProcessor {
    private static final String TAG_NAME = "transactionDescription";
    private static final int PRECEDENCE = 1000;

    public TransactionDescriptionTagProcessor(String dialectPrefix) {
        super(TemplateMode.HTML, dialectPrefix, TAG_NAME, true, null, false, PRECEDENCE);
    }

    @Override
    protected void doProcess(ITemplateContext context, IProcessableElementTag tag, 
                            IElementTagStructureHandler structureHandler) {
        Object descObj = context.getVariable("description");
        if (descObj == null) return;
        
        String unsafeHtml = descObj.toString();
        IModel model = context.getModelFactory().createModel();
        model.add(context.getModelFactory().createText(unsafeHtml));
        
        structureHandler.replaceWith(model, false);
    }
}