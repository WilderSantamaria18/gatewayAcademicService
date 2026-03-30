package pe.edu.idat.app_gateway.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

@RestController
@RequiredArgsConstructor
public class UsuariosProxyController {

    private static final String AUTH_SERVICE_USUARIOS_URL = "http://localhost:8081/api/usuarios";

    @GetMapping({"/api/usuarios", "/api/usuarios/"})
    public ResponseEntity<String> listarUsuarios(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        HttpHeaders headers = new HttpHeaders();
        if (authorization != null && !authorization.isBlank()) {
            headers.set("Authorization", authorization);
        }

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
