package pe.edu.idat.app_gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class FiltroJwtAuth extends OncePerRequestFilter {

    private final IJwtService jwtService;

    public FiltroJwtAuth(IJwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        System.out.println("DEBUG-GATEWAY: Recibida petición en -> " + requestUri + " [" + request.getMethod() + "]");

        // HU-01/02: Omitir validación de JWT para registro y login.
        // Se usa una comprobación más robusta que cubra "/auth-service/api/auth" con o sin "/" final.
        if (requestUri != null && (requestUri.startsWith("/auth-service/api/auth/") || requestUri.equals("/auth-service/api/auth"))) {
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            String token = jwtService.extraerTokenUsuario(request);
            
            if (token == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Token requerido\"}");
                return;
            }
            
            if (!jwtService.validarToken(token)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Token inválido o expirado\"}");
                return;
            }
            
            Claims claims = jwtService.obtenerClaims(token);
            jwtService.generarAutenticacion(claims);

            if (requestUri.startsWith("/auth-service/api/usuarios")) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                boolean isAdmin = authentication != null
                        && authentication.getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
                if (!isAdmin) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Acceso denegado: requiere ROLE_ADMIN\"}");
                    return;
                }
            }

            // Envolver la petición cubriendo getHeader, getHeaders y getHeaderNames para ProxyExchange
            HttpServletRequestWrapper wrappedRequest = new HttpServletRequestWrapper(request) {
                @Override
                public String getHeader(String name) {
                    if ("Authorization".equalsIgnoreCase(name)) {
                        return "Bearer " + token;
                    }
                    return super.getHeader(name);
                }

                @Override
                public java.util.Enumeration<String> getHeaders(String name) {
                    if ("Authorization".equalsIgnoreCase(name)) {
                        return java.util.Collections.enumeration(java.util.Collections.singletonList("Bearer " + token));
                    }
                    return super.getHeaders(name);
                }

                @Override
                public java.util.Enumeration<String> getHeaderNames() {
                    java.util.List<String> names = java.util.Collections.list(super.getHeaderNames());
                    boolean hasAuth = false;
                    for (String headerName : names) {
                        if ("Authorization".equalsIgnoreCase(headerName)) {
                            hasAuth = true;
                            break;
                        }
                    }
                    if (!hasAuth) {
                        names.add("Authorization");
                    }
                    return java.util.Collections.enumeration(names);
                }
            };

            filterChain.doFilter(wrappedRequest, response);
            
        } catch (JwtException ex) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"JWT inválido: " + ex.getMessage() + "\"}");
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Error interno filtro JWT: " + ex.getMessage() + "\"}");
        }
    }
}
