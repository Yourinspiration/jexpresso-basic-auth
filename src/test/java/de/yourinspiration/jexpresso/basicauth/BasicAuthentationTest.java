package de.yourinspiration.jexpresso.basicauth;

import io.netty.handler.codec.http.HttpMethod;

import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import de.yourinspiration.jexpresso.Next;
import de.yourinspiration.jexpresso.Request;
import de.yourinspiration.jexpresso.Response;
import de.yourinspiration.jexpresso.baseauth.PasswordEncoder;
import de.yourinspiration.jexpresso.baseauth.UserDetails;
import de.yourinspiration.jexpresso.baseauth.UserDetailsService;
import de.yourinspiration.jexpresso.baseauth.UserNotFoundException;

/**
 * Test case for {@link BasicAuthentation}.
 * 
 * @author Marcel Härle
 *
 */
public class BasicAuthentationTest {

    private BasicAuthentation basicAuthentication;

    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private Request request;
    @Mock
    private Response response;
    @Mock
    private Next next;
    @Mock
    private UserDetails userDetails;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        basicAuthentication = new BasicAuthentation(userDetailsService, passwordEncoder);
    }

    @Test
    public void testSuccessfulAuthentication() throws UserNotFoundException {
        final String path = "/test/path";
        final String authorities = "";
        final HttpMethod[] methods = new HttpMethod[] { HttpMethod.GET };

        basicAuthentication.securePath(path, authorities, methods);

        Mockito.when(request.path()).thenReturn(path);
        Mockito.when(request.method()).thenReturn(HttpMethod.GET);
        Mockito.when(request.get("Authorization")).thenReturn("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        Mockito.when(userDetailsService.loadUserByUsername("Aladdin")).thenReturn(userDetails);

        Mockito.when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());
        Mockito.when(userDetails.getUsername()).thenReturn("Aladdin");
        Mockito.when(userDetails.getPassword()).thenReturn("open sesame");

        Mockito.when(passwordEncoder.encode("open sesame")).thenReturn("open sesame");
        Mockito.when(passwordEncoder.checkpw("open sesame", "open sesame")).thenReturn(true);

        basicAuthentication.handle(request, response, next);

        Mockito.verify(request).attribute("userDetails", userDetails);
        Mockito.verify(next).next();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUserNotFound() throws UserNotFoundException {
        final String path = "/test/path";
        final String authorities = "";
        final HttpMethod[] methods = new HttpMethod[] { HttpMethod.GET };

        basicAuthentication.securePath(path, authorities, methods);

        Mockito.when(request.path()).thenReturn(path);
        Mockito.when(request.method()).thenReturn(HttpMethod.GET);
        Mockito.when(request.get("Authorization")).thenReturn("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        Mockito.when(userDetailsService.loadUserByUsername("Aladdin")).thenThrow(UserNotFoundException.class);

        basicAuthentication.handle(request, response, next);

        Mockito.verify(next).cancel();
    }

    @Test
    public void testForFalsePassword() throws UserNotFoundException {
        final String path = "/test/path";
        final String authorities = "";
        final HttpMethod[] methods = new HttpMethod[] { HttpMethod.GET };

        basicAuthentication.securePath(path, authorities, methods);

        Mockito.when(request.path()).thenReturn(path);
        Mockito.when(request.method()).thenReturn(HttpMethod.GET);
        Mockito.when(request.get("Authorization")).thenReturn("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        Mockito.when(userDetailsService.loadUserByUsername("Aladdin")).thenReturn(userDetails);

        Mockito.when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());
        Mockito.when(userDetails.getUsername()).thenReturn("Aladdin");
        Mockito.when(userDetails.getPassword()).thenReturn("open another sesame");

        Mockito.when(passwordEncoder.encode("open another sesame")).thenReturn("open another sesame");
        Mockito.when(passwordEncoder.checkpw("open sesame", "open another sesame")).thenReturn(false);

        basicAuthentication.handle(request, response, next);

        Mockito.verify(next).cancel();
    }

}