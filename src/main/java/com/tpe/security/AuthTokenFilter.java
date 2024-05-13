package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = parseJwt(request);
        try {
            if(jwtToken != null && jwtUtils.validateToken(jwtToken)){
                String userName = jwtUtils.getUsernameFromJwtToken(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }
        // !!! mevcut filtrenin işlemini tamamlayıp istek ve yanıtı filtre zincirindeki sonraki
        //  adıma (bir sonraki filtre veya hedef servlet) aktarmak için kullanılır.
        filterChain.doFilter(request,response);
    }

    private String parseJwt(HttpServletRequest request){
        //!!! requestin header kısmındaki Authorization olarak eklenen key degerin value kismina
        // JWT token eklenirken "Bearer " ile on ek eklenir.
        String header = request.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7); // Bearer sjdkhsdksahkjdhakjdhaksj
        }

        return null;
    }
    // !!! alttaki methodun permitAll() dan farki : doFilterInternal metodunda, gelen
    //  isteklerdeki JWT token'ları çözümlenir ve doğrulanır. Ancak, bazı istekler
    //  (yine /register, /login gibi) için bu token işleme sürecinin gereksiz olduğunu
    //  belirtmek için shouldNotFilter metodu kullanılır.
    // !!! Neden Gerekli: WebSecurityConfig'te permitAll() ile bu endpoint'lerin kimlik
    //  doğrulama gerektirmediğini belirtmiş olsanız da, AuthTokenFilter varsayılan
    //  olarak tüm istekleri işleyecektir. Bu, kayıt veya giriş işlemleri gibi kimlik
    //  doğrulaması gerektirmeyen işlemler için gereksiz bir işlem yükü oluşturabilir.
    //  shouldNotFilter metodu, bu gereksiz işlemi önlemek için kullanılır.

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antMatcher = new AntPathMatcher();
        return antMatcher.match("/register", request.getServletPath()) ||
                antMatcher.match("/login", request.getServletPath());
    }
}