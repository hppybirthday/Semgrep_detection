package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/job")
public class JobController {
    private Map<Long, JobLog> jobLogs = new HashMap<>();

    @GetMapping("/create")
    public ModelAndView createJobForm() {
        return new ModelAndView("jobForm");
    }

    @PostMapping("/submit")
    public ModelAndView submitJob(@RequestParam String triggerMsg, @RequestParam String handleMsg) {
        Long id = (long) (jobLogs.size() + 1);
        jobLogs.put(id, new JobLog(id, triggerMsg, handleMsg));
        return new ModelAndView("redirect:/job/view?id=" + id);
    }

    @GetMapping("/view")
    public ModelAndView viewJob(@RequestParam Long id) {
        JobLog log = jobLogs.getOrDefault(id, new JobLog(0L, "Not Found", "Not Found"));
        ModelAndView mav = new ModelAndView("jobView");
        mav.addObject("jobLog", log);
        return mav;
    }

    private static class JobLog {
        private Long id;
        private String triggerMsg;
        private String handleMsg;

        public JobLog(Long id, String triggerMsg, String handleMsg) {
            this.id = id;
            this.triggerMsg = triggerMsg;
            this.handleMsg = handleMsg;
        }

        public Long getId() { return id; }
        public String getTriggerMsg() { return triggerMsg; }
        public String getHandleMsg() { return handleMsg; }
    }
}

// View Template (jobView.jsp):
// <html>
// <body>
// <h2>Job Log Details</h2>
// <p>ID: ${jobLog.id}</p>
// <p>Trigger Message: ${jobLog.triggerMsg}</p>
// <p>Handle Message: ${jobLog.handleMsg}</p>
// </body>
// </html>