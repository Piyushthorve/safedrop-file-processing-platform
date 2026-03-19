package com.cloudProject.cloudP.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Component
public class SecurityErrorHandlers {

    private final ObjectMapper mapper;   // <-- inject, don’t create

    public final AuthenticationEntryPoint unauthorized = (request, response, authException) ->
            write(response, request, HttpStatus.UNAUTHORIZED, "Unauthorized", "Missing or invalid token");

    public final AccessDeniedHandler forbidden = (request, response, accessDeniedException) ->
            write(response, request, HttpStatus.FORBIDDEN, "Forbidden", "Not enough permissions");

    public SecurityErrorHandlers(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    private void write(HttpServletResponse response,
                       HttpServletRequest request,
                       HttpStatus status,
                       String error,
                       String message) throws IOException {

        ApiError body = ApiError.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(error)
                .message(message)
                .path(request.getRequestURI())
                .details(Map.of())
                .build();

        response.setStatus(status.value());
        response.setContentType("application/json");
        mapper.writeValue(response.getWriter(), body);
    }
}
