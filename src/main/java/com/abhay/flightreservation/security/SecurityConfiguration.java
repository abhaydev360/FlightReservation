package com.abhay.flightreservation.security;

import java.util.ArrayList;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

	private final String WEB_URL = "/WEB-INF/jsps/";

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//		http.authorizeHttpRequests()
//				.requestMatchers(WEB_URL + "login/registerUser.jsp", WEB_URL + "login/login.jsp",
//						WEB_URL + "CompleteReservation.jsp", WEB_URL + "displayFlights.jsp",
//						WEB_URL + "findFlights.jsp", WEB_URL + "reservationConfirmation.jsp", "/showReg", "/",
//						"/index.html", "/registerUser", "/login", "/showLogin", "/findFlights",
//						"/showCompleteReservation", "/CompleteReservation", "", "/login/*")
//				.permitAll().requestMatchers("/admin/showAddFlight/**").hasAuthority("ADMIN").anyRequest()
//				.authenticated().and().csrf().disable();
//		return http.build();

		return http.csrf().disable().authorizeHttpRequests()
				.requestMatchers(WEB_URL + "login/registerUser.jsp", WEB_URL + "login/login.jsp", "/showReg", "/",
						"/index.html", "/registerUser", "/login", "/showLogin")
				.permitAll().and().authorizeHttpRequests().requestMatchers("/admin/**").hasAnyAuthority("ADMIN")
				.anyRequest().authenticated().and().build();

	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		final List<GlobalAuthenticationConfigurerAdapter> configurers = new ArrayList<>();
		configurers.add(new GlobalAuthenticationConfigurerAdapter() {
			@Override
			public void configure(AuthenticationManagerBuilder auth) throws Exception {
				// auth.doSomething()
			}
		});
		return authConfig.getAuthenticationManager();
	}

}
