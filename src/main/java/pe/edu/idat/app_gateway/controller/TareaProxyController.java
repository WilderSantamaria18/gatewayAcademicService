package pe.edu.idat.app_gateway.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

/**
 * Proxy manual para /api/tareas
 * Resuelve el bloqueo de seguridad nativa del Gateway MVC que elimina la cabecera Authorization 
 * al hacer proxy hacia los microservicios por razones de seguridad anti-fugas.
 */
@RestController
public class TareaProxyController {

    private static final String TASK_SERVICE_URL = "http://localhost:8083/api/tareas";

    @PostMapping({"/api/tareas", "/api/tareas/"})
    public ResponseEntity<String> crearTareaProxy(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody String body) {

        if (authorization == null || authorization.isBlank()) {
            return ResponseEntity.status(401).body("{\"error\": \"Token no proporcionado al Gateway\"}");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", authorization);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    TASK_SERVICE_URL,
                    HttpMethod.POST,
                    entity,
                    String.class
            );
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (HttpStatusCodeException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getResponseBodyAsString());
        }
    }
}
