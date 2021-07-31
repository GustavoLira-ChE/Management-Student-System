package com.github.innovaccionvirtual.web;

import com.github.innovaccionvirtual.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class HomeController {
    @Autowired
    PasswordEncoder encoder;

    @GetMapping("/")
    public String root() {
        return "index";
    }

    @GetMapping("/user")
    public String userIndex() {
        return "user/index";
    }

    @GetMapping("/login")
    public String login(@ModelAttribute User user) {
        return "login";
    }

    @GetMapping("login-error")
    public ModelAndView login() {
        return new ModelAndView("login", "error", true);
    }

    /*@GetMapping("/login")
    public String login(@ModelAttribute User user) {
        return "index";
    }*/

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "/error/access-denied";
    }
}
