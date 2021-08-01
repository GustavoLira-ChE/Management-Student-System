package com.github.innovaccionvirtual.config;

import com.github.innovaccionvirtual.security.services.UserDetailsServiceImpl;
import com.github.innovaccionvirtual.web.LoggingAccessDeniedHandler;
import com.github.innovaccionvirtual.web.LoggingAccessSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private LoggingAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private LoggingAccessSuccessHandler accessSuccessHandler;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        // Setting Service to find User in the database.
        // And Setting PassswordEncoder
        //auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());

    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.authorizeRequests().antMatchers("/", "/login", "/logout").permitAll();

        http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')");

        http.authorizeRequests().antMatchers("/panel", "/profile/**").access("hasAnyRole('ROLE_USER', 'ROLE_TEACHER', "
                + "'ROLE_ADMIN')");

        http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");

        http.authorizeRequests().and().formLogin()
                .loginProcessingUrl("/j_spring_security_check")
                .loginPage("/login")
                .defaultSuccessUrl("/panel")
                .failureUrl("/login?error=true")
                .usernameParameter("username")
                .passwordParameter("password")
                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessful");
    }
    
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("student").password("{noop}123").roles("USER")
                .and()
                .withUser("teacher").password("{noop}password").roles("MANAGER")
                .and()
                .withUser("admin").password("{noop}password").roles("ADMIN");
    }
}
