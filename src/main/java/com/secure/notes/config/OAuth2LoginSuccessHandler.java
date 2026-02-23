package com.secure.notes.config;

import java.io.*;
import java.util.*;

import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.models.enums.AppRole;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.security.jwt.JwtUtils;
import com.secure.notes.security.services.UserDetailsImpl;
import com.secure.notes.services.UserService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.*;
import lombok.extern.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final RoleRepository roleRepository;

    @Value("${frontend.url}")
    private String frontendUrl;


    private String username;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws ServletException, IOException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;

        DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = principal.getAttributes();

        String provider = token.getAuthorizedClientRegistrationId();

        String email = (String) attributes.get("email");
        String name = String.valueOf(attributes.getOrDefault("name", ""));

        String idAttributeKey;

        // FIX APPLIED — Clean provider branching with correct braces
        if ("github".equals(provider)) {

            username = String.valueOf(attributes.getOrDefault("login", ""));
            idAttributeKey = "id";

            // FIX APPLIED — GitHub may not return email
            if (email == null || email.isBlank()) {
                email = username + "@github.local";
            }

        } else if ("google".equals(provider)) {

            username = email.split("@")[0];
            idAttributeKey = "sub";

        } else {

            username = "user";
            idAttributeKey = "id";
        }

        log.info("HELLO OAUTH: {} : {} : {}", email, name, username);

        String finalEmail = email;
        String finalIdKey = idAttributeKey;

        userService.findByEmail(finalEmail)
                .ifPresentOrElse(user -> {

                    DefaultOAuth2User oauthUser =
                            new DefaultOAuth2User(
                                    List.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name())),
                                    attributes,
                                    finalIdKey
                            );

                    Authentication newAuth =
                            new OAuth2AuthenticationToken(
                                    oauthUser,
                                    oauthUser.getAuthorities(),
                                    provider
                            );

                    SecurityContextHolder.getContext().setAuthentication(newAuth);

                }, () -> {

                    User newUser = new User();
                    Role role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Default role not found"));

                    newUser.setRole(role);
                    newUser.setEmail(finalEmail);
                    newUser.setUserName(username);
                    newUser.setSignUpMethod(provider);

                    userService.registerUser(newUser);

                    DefaultOAuth2User oauthUser =
                            new DefaultOAuth2User(
                                    List.of(new SimpleGrantedAuthority(role.getRoleName().name())),
                                    attributes,
                                    finalIdKey
                            );

                    Authentication newAuth =
                            new OAuth2AuthenticationToken(
                                    oauthUser,
                                    oauthUser.getAuthorities(),
                                    provider
                            );

                    SecurityContextHolder.getContext().setAuthentication(newAuth);
                });

        // FIX APPLIED — Always use updated authentication
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        DefaultOAuth2User oauth2User = (DefaultOAuth2User) currentAuth.getPrincipal();

        String jwtEmail = (String) oauth2User.getAttributes().get("email");

        if (jwtEmail == null || jwtEmail.isBlank()) {
            jwtEmail = username + "@github.local";
        }

        User user = userService.findByEmail(jwtEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Set<SimpleGrantedAuthority> authorities =
                Set.of(new SimpleGrantedAuthority(user.getRole().getRoleName().name()));

        UserDetailsImpl userDetails = new UserDetailsImpl(
                null,
                username,
                jwtEmail,
                null,
                false,
                authorities
        );

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        String targetUrl = UriComponentsBuilder
                .fromUriString(frontendUrl + "/oauth2/redirect")
                .queryParam("token", jwtToken)
                .build()
                .toUriString();

        this.setAlwaysUseDefaultTargetUrl(true);
        this.setDefaultTargetUrl(targetUrl);

        super.onAuthenticationSuccess(request, response, currentAuth);
    }
}