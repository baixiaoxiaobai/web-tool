package com.tools.auth.server.oauth2.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface AccountUserDetailService extends UserDetailsService {

    UserDetails loadUserByUsername(String var1,String var2,String var3) throws UsernameNotFoundException;
}
