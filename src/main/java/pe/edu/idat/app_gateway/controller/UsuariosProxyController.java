package pe.edu.idat.app_gateway.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

/**
 * T-010: Proxy para /api/usuarios (protegido para ROLE_ADMIN)
 */
@RestController
public class UsuariosProxyController {

    private static final String AUTH_SERVICE_USUARIOS_URL = "http://localhost:8081/api/usuarios";

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping({"/api/usuarios", "/api/usuarios/"})
    public ResponseEntity<String> listarUsuarios(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        if (authorization == null || authorization.isBlank()) {
            return ResponseEntity.status(401).body("{\"error\": \"Token no proporcionado\"}");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authorization);

        HttpEntity<Void> entity = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    AUTH_SERVICE_USUARIOS_URL,
                    HttpMethod.GET,
                    entity,
                    String.class
            );
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (HttpStatusCodeException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getResponseBodyAsString());
        }
    }
}
