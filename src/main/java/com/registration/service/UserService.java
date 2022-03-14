package com.registration.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.registration.model.User;
import com.registration.web.dto.UserRegistrationDto;

public interface UserService extends UserDetailsService{
	User save (UserRegistrationDto registrationDto);



}
