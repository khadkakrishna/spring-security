package com.development;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
				.defaultSuccessUrl("/hello", true)
				.failureUrl("/login?error")
				.permitAll()
				.and()
			.logout()
				.permitAll();
	}

	@Override
	protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
	    auth.inMemoryAuthentication()
        	.withUser("user").password(passwordEncoder().encode("pass")).roles("USER")
        	.and()	        
        	.withUser("dummy").password(passwordEncoder().encode("password")).roles("USER")
        	.and()
	        .withUser("dummy2").password(passwordEncoder().encode("password2")).roles("USER")
	        .and()
	        .withUser("admin").password(passwordEncoder().encode("adminPass")).roles("ADMIN");
	}
	
	@Bean 
	public PasswordEncoder passwordEncoder() { 
	    return new BCryptPasswordEncoder(); 
	}
}