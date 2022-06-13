package com.tools.auth.server.oauth2.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.tools.auth.server.oauth2.feign.SysUserClient;
import com.tools.auth.server.oauth2.service.AccountUserDetailService;
import com.tools.common.core.model.SysUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import java.util.ArrayList;
import java.util.List;

@Configuration
@Slf4j
public class UserDetailsServiceImpl implements AccountUserDetailService {


    @Autowired
    private UserService userService;

    @Autowired
    private SysUserClient sysUserClient;

    @Autowired
    private SysUserService sysUserService;

    @Autowired
    private SysUserRoleService sysUserRoleService;

    @Autowired
    private SysRoleService sysRoleService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username,String password, String grantType) throws OAuth2Exception {
        List<GrantedAuthority> grantedAuthorities=new ArrayList<>();
        if(grantType.equals("sys_password")){
            SysUser sysUser = sysUserClient.findByUsername(username);
            if(sysUser==null){
                throw new AuthenticationCredentialsNotFoundException("用户不存在");
            }
            if(!passwordEncoder.matches(password,sysUser.getPassword())){
                throw new BadCredentialsException("密码错误");
            }
            if(sysUser.getStatus()==0){
                throw new DisabledException("用户已停用");
            }
            //获取用户角色
            SysUserRole sysUserRole = sysUserRoleService.getOne(new QueryWrapper<SysUserRole>().eq("user_id",sysUser.getUserId()));
            String[] roles=sysUserRole.getRoleId().split(",");
            for (int i=0;i<roles.length;i++){
                SysRole sysRole = sysRoleService.getById(roles[i]);
                grantedAuthorities.add(new SimpleGrantedAuthority(sysRole.getRoleName()));
            }
            SecurityUser securityUser = new SecurityUser();
            BeanUtils.copyProperties(sysUser, securityUser);
            securityUser.setGrantedAuthorities(grantedAuthorities);
            return securityUser;
        }
        if(grantType.equals("password")){
            com.jx3.wbl.entity.User user = userService.selectByUserName(username);
            System.out.println(user.getPassword());
            SecurityUser securityUser = new SecurityUser();
            BeanUtils.copyProperties(user, securityUser);
            System.out.println(securityUser.getPassword());
            if(securityUser==null){
                throw new AuthenticationCredentialsNotFoundException("用户不存在");
            }
            if(!passwordEncoder.matches(password,securityUser.getPassword())){
                throw new BadCredentialsException("密码错误");
            }
            if(securityUser.isEnabled()==false){
                throw new DisabledException("用户已停用");
            }
            return securityUser;
        }
        return null;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("----------UserDetailsServiceImpl-------------");
        com.jx3.wbl.entity.User user = userService.selectByUserName(username);
        System.out.println(user.getPassword());
        SecurityUser securityUser = new SecurityUser();
        BeanUtils.copyProperties(user, securityUser);
        System.out.println(securityUser.getPassword());
        if (securityUser == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        if (!securityUser.isEnabled()) {
            throw new DisabledException("禁止登录");
        }
        return securityUser;
    }
}
