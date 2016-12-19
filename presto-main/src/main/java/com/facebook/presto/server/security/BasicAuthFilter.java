/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.server.security;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.net.HttpHeaders;
import com.sun.security.auth.UserPrincipal;
import io.airlift.log.Logger;

import javax.annotation.PreDestroy;
import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Base64;
import java.util.Optional;
import java.util.Properties;

import static com.google.common.io.ByteStreams.copy;
import static com.google.common.io.ByteStreams.nullOutputStream;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

public class BasicAuthFilter
        implements Filter
{
    private static final Logger LOG = Logger.get(BasicAuthFilter.class);
    private static final String NEGOTIATE_SCHEME = "Basic";

    private final boolean onlyValidateHttps;
    private ImmutableMap<String, String> authenticationMapping;

    @Inject
    public BasicAuthFilter(SecurityConfig config)
    {
        onlyValidateHttps = config.isBasicAuthHttpsOnly();
        String credentialsFile = config.getBasicAuthCredentialsFile();
        Properties properties = new Properties();
        try (FileReader reader = new FileReader(credentialsFile)) {
            properties.load(reader);
        }
        catch (FileNotFoundException e) {
            LOG.error(e, "The http basic auth %s configuration file can not be found", credentialsFile);
        }
        catch (IOException e) {
            LOG.error(e, "I/O Exception during loading http basic configuration %s", credentialsFile);
        }
        authenticationMapping = Maps.fromProperties(properties);
    }

    @PreDestroy
    public void shutdown()
    {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain nextFilter)
            throws IOException, ServletException
    {
        // skip auth for http
        if (onlyValidateHttps && !servletRequest.isSecure()) {
            nextFilter.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null) {
            String[] parts = header.split("\\s+");
            if (parts.length == 2 && parts[0].equals(NEGOTIATE_SCHEME)) {
                Optional<Principal> user = authenticate(parts[1]);
                if (user.isPresent()) {
                    nextFilter.doFilter(new HttpServletRequestWrapper(request)
                    {
                        @Override
                        public Principal getUserPrincipal()
                        {
                            return user.get();
                        }
                    }, servletResponse);
                    return;
                }
            }
        }

        sendChallenge(request, response);
    }
    private Optional<Principal> authenticate(String token)
    {
        String credentials = new String(Base64.getDecoder().decode(token));
        String[] parts = credentials.split(":", 2);

        if (parts.length == 2 &&
                authenticationMapping.containsKey(parts[0]) &&
                authenticationMapping.get(parts[0]).equals(parts[1])) {
            return Optional.of(new UserPrincipal(parts[0]));
        }

        return Optional.empty();
    }

    private static void sendChallenge(HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        // If we send the challenge without consuming the body of the request,
        // the Jetty server will close the connection after sending the response.
        // The client interprets this as a failed request and does not resend
        // the request with the authentication header.
        // We can avoid this behavior in the Jetty client by reading and discarding
        // the entire body of the unauthenticated request before sending the response.
        try (InputStream inputStream = request.getInputStream()) {
            copy(inputStream, nullOutputStream());
        }

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                String.format("%s realm=\"presto\"", NEGOTIATE_SCHEME));
        response.setStatus(SC_UNAUTHORIZED);
    }

    @Override
    public void init(FilterConfig filterConfig)
            throws ServletException
    {
    }

    @Override
    public void destroy()
    {
    }
}
