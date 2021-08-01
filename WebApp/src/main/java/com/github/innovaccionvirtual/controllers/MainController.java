package com.github.innovaccionvirtual.controllers;

import com.github.innovaccionvirtual.models.User;
import com.github.innovaccionvirtual.security.services.UserDetailsImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class MainController {

    @GetMapping(value = {"/", "/welcome"})
    public String welcomePage(Model model, Principal principal) {
        if (principal != null) {
            model.addAttribute("user", ((UserDetailsImpl) ((Authentication) principal).getPrincipal()));
        }

        model.addAttribute("title", "Bienvenido!");
        return "index";
    }

    @GetMapping("/panel")
    public String panelPage(Model model, Principal principal) {
        UserDetailsImpl user = ((UserDetailsImpl) ((Authentication) principal).getPrincipal());
        if (user.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER"))) {
            model.addAttribute("user", ((UserDetailsImpl) ((Authentication) principal).getPrincipal()));
            return "userpage";
        }
        return "redirect:/";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("isLoginPage", true);
        model.addAttribute("title", "Iniciar sesion");
        return "login";
    }

    @GetMapping("/logoutSuccessful")
    public String logoutSuccessfulPage(Model model) {
        return "redirect:/";
    }

    @GetMapping("/profile/school")
    public String schoolPage(Model model, Principal principal) {
        UserDetailsImpl user = ((UserDetailsImpl) ((Authentication) principal).getPrincipal());
        model.addAttribute("userInfo", user.toString());
        model.addAttribute("inst-page", "google.com");
        model.addAttribute("inst-name", "Nombre de la institución: Escuela Publica Secundaria");
        model.addAttribute("user", ((UserDetailsImpl) ((Authentication) principal).getPrincipal()));
        return "schoolardata";
    }

    @GetMapping("/profile")
    public String profilePage(Model model, Principal principal) {
        model.addAttribute("user", ((UserDetailsImpl) ((Authentication) principal).getPrincipal()));

        return "personaldata";
    }

    @GetMapping("/advisory")
    public String advisory(Model model, Principal principal) {
        if (principal != null) {
            model.addAttribute("user", ((UserDetailsImpl) ((Authentication) principal).getPrincipal()));
        }

        return "advisory";
    }

    @GetMapping("/403")
    public String accessDenied(Model model, Principal principal) {

        if (principal != null) {
            UserDetailsImpl loginedUser = (UserDetailsImpl) ((Authentication) principal).getPrincipal();


            model.addAttribute("userInfo", loginedUser.toString());

            String message = "Hi " + principal.getName() //
                    + "<br> You do not have permission to access this page!";
            model.addAttribute("message", message);

        }

        return "denegado";
    }


}
