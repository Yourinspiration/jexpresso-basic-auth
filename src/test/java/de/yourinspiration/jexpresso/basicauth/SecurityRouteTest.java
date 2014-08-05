package de.yourinspiration.jexpresso.basicauth;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import io.netty.handler.codec.http.HttpMethod;

import org.junit.Before;
import org.junit.Test;

/**
 * Test case for {@link SecurityRoute}.
 * 
 * @author Marcel Härle
 *
 */
public class SecurityRouteTest {

    private SecurityRoute securityRoute;

    private final String path = "/test/path";
    private final String authorities = "USER";
    private final HttpMethod[] methods = new HttpMethod[] { HttpMethod.GET };

    @Before
    public void setUp() {
        securityRoute = new SecurityRoute(path, authorities, methods);
    }

    @Test
    public void testGetPath() {
        assertEquals(path, securityRoute.getPath());
    }

    @Test
    public void testGetAuthorities() {
        assertEquals(authorities, securityRoute.getAuthorities());
    }

    @Test
    public void testGetMethods() {
        assertArrayEquals(methods, securityRoute.getMethods());
    }

    @Test
    public void testMatchesPathAndMethod() {
        assertTrue(securityRoute.matchesPathAndMethod(path, HttpMethod.GET));
        assertFalse(securityRoute.matchesPathAndMethod("/false/path", HttpMethod.GET));
        assertFalse(securityRoute.matchesPathAndMethod(path, HttpMethod.POST));
        assertFalse(securityRoute.matchesPathAndMethod("/false/path", HttpMethod.POST));
    }

}
