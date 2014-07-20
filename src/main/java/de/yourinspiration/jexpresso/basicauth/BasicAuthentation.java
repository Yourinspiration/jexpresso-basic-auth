package de.yourinspiration.jexpresso.basicauth;

import io.netty.handler.codec.http.HttpMethod;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.pmw.tinylog.Logger;

import de.yourinspiration.jexpresso.MiddlewareHandler;
import de.yourinspiration.jexpresso.Next;
import de.yourinspiration.jexpresso.Request;
import de.yourinspiration.jexpresso.Response;
import de.yourinspiration.jexpresso.basisauth.impl.SecurityRoute;
import de.yourinspiration.jexpresso.http.HttpStatus;

public class BasicAuthentation implements MiddlewareHandler {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    private final List<SecurityRoute> securityRoutes = new ArrayList<>();

    public BasicAuthentation(final UserDetailsService userDetailsService, final PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    public void securePath(String path, String authorities, HttpMethod... methods) {
        securityRoutes.add(new SecurityRoute(path, authorities, methods));
    }

    @Override
    public void handle(Request request, Response response, Next next) {
        if (checkSecurityProviders(request, response)) {
            next.next();
        } else {
            next.cancel();
        }
    }

    /**
     * Check if there is a security entry for the path and method.
     * 
     * @param request
     *            the current request
     * @param response
     *            the current response
     * @return returns <code>true</code> if the path was public or the user was
     *         successfully authenticated, otherwise <code>false</code>
     */
    private boolean checkSecurityProviders(final Request request, final Response response) {
        final String path = request.path();
        final HttpMethod method = request.method();

        for (SecurityRoute route : securityRoutes) {
            if (route.matchesPathAndMethod(path, method)) {
                final boolean authenticated = checkAuthentication(request, userDetailsService, passwordEncoder);
                if (!authenticated) {
                    handleUnauthenticated(response);
                    return false;
                } else {
                    return true;
                }
            }
        }

        return true;
    }

    private void handleUnauthenticated(final Response response) {
        response.status(HttpStatus.UNAUTHORIZED);
        response.set("WWW-Authenticate", "Basic realm=\"sparkle realm\"");
        response.type("text/plain");
        response.send("");
    }

    private boolean checkAuthentication(Request request, final UserDetailsService userDetailsService,
            final PasswordEncoder passwordEncoder) {
        boolean authenticated = false;

        final String authorization = request.get("Authorization");

        if (authorization != null && authorization.startsWith("Basic")) {
            // Authorization: Basic base64credentials
            final String base64Credentials = authorization.substring("Basic".length()).trim();
            final String credentials = new String(Base64.getDecoder().decode(base64Credentials),
                    Charset.forName("UTF-8"));

            // credentials = username:password
            final String[] values = credentials.split(":", 2);

            try {
                final UserDetails userDetails = userDetailsService.loadUserByUsername(values[0]);

                if (userDetails != null && passwordEncoder.checkpw(values[1], userDetails.getPassword())) {
                    final String authorities = getAuthoritiesForRoute(request.path(), request.method());

                    if (hasGrantedAuthoriy(userDetails, authorities)) {
                        request.attribute("userDetails", userDetails);
                        authenticated = true;
                    }
                }
            } catch (UserNotFoundException e) {
                Logger.debug("User not found", e);
            }
        }

        return authenticated;
    }

    private String getAuthoritiesForRoute(final String path, final HttpMethod method) {
        for (SecurityRoute securityRoute : securityRoutes) {
            if (securityRoute.matchesPathAndMethod(path, method)) {
                return securityRoute.getAuthorities();
            }
        }
        return "";
    }

    private boolean hasGrantedAuthoriy(final UserDetails userDetails, final String authorities) {
        boolean authorityFound = false;

        for (GrantedAuthority grantedAuthority : userDetails.getAuthorities()) {
            for (String authority : authorities.split(",")) {
                if (grantedAuthority.getAuthority().equalsIgnoreCase(authority)) {
                    authorityFound = true;
                    break;
                }
            }
        }

        return authorityFound;
    }

}
