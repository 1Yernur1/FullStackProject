package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;


@Configuration
public class ProjectSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.cors().configurationSource(request ->
				{
					CorsConfiguration configuration = new CorsConfiguration();
					configuration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
					configuration.setAllowedMethods(Collections.singletonList("*"));
					configuration.setAllowCredentials(true);
					configuration.setAllowedHeaders(Collections.singletonList("*"));
					configuration.setMaxAge(3600L);
					return configuration;
				}).and()
				.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.authorizeRequests()
				.antMatchers("/myAccount").authenticated()
				.antMatchers("/myBalance").authenticated()
				.antMatchers("/myLoans").authenticated()
				.antMatchers("/myCards").authenticated()
				.antMatchers("/notices").permitAll()
				.antMatchers("/contact").permitAll()
				.and().formLogin()
				.and().httpBasic();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
