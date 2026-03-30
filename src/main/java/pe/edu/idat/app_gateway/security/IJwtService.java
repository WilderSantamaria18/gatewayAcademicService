package pe.edu.idat.app_gateway.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;

public interface IJwtService {
    // Valida que el token sea correcto y no este vencido
    boolean validarToken(String token);

    // Extrae los claims (datos) del token
    Claims obtenerClaims(String token);

    // Extrae el token del header Authorization (Bearer <token>)
    String extraerTokenUsuario(HttpServletRequest request);

    // Genera la autenticacion en el SecurityContextHolder
    void generarAutenticacion(Claims claims);
}
