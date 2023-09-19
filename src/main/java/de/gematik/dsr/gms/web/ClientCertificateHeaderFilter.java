/*
 * Copyright 2023 gematik GmbH
 *
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

package de.gematik.dsr.gms.web;

import static de.gematik.dsr.gms.web.WebServiceConstants.X_CLIENT_CERTIFICATE_HEADER;

import de.gematik.dsr.gms.application.ClientCertificateHolder;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.idp.crypto.CryptoLoader;
import io.quarkus.runtime.util.StringUtil;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.UUID;
import org.jboss.logging.Logger;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class ClientCertificateHeaderFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(ClientCertificateHeaderFilter.class);

  @Inject ClientCertificateHolder clientCertificateHolder;

  @Override
  public void filter(final ContainerRequestContext requestContext) throws IOException {

    // Exceptions for the endpoints without mTLS
    //  GET   /nonce
    //  POST  /register-device
    if (!(requestContext.getMethod().equals(HttpMethod.GET)
            && requestContext.getUriInfo().getPath().endsWith("/nonce"))
        && !(requestContext.getMethod().equals(HttpMethod.POST)
            && requestContext.getUriInfo().getPath().endsWith("/register-device"))) {

      final String urlEncodedClientCertificate =
          requestContext.getHeaderString(X_CLIENT_CERTIFICATE_HEADER.getValue());
      if (StringUtil.isNullOrEmpty(urlEncodedClientCertificate)) {
        LOG.infof("Missing '%s' header", X_CLIENT_CERTIFICATE_HEADER.getValue());
        throw new WebApplicationException(Response.Status.UNAUTHORIZED);
      } else {
        try {
          // Note: NGINX $ssl_client_escaped_cert returns the client certificate
          // in the PEM format (urlencoded) for an established SSL connection
          final String decodedClientCertificate =
              URLDecoder.decode(urlEncodedClientCertificate, StandardCharsets.UTF_8);

          final X509Certificate clientCertificate =
              CryptoLoader.getCertificateFromPem(
                  decodedClientCertificate.getBytes(StandardCharsets.UTF_8));
          clientCertificateHolder.setClientCertificate(clientCertificate);
        } catch (Exception e) {
          final UUID traceId = UUID.randomUUID();
          LOG.infof("%s %s", traceId, e.getLocalizedMessage());
          throw new GMServiceRuntimeException(
              GMServiceExceptionReason.INVALID_CLIENT_CERTIFICATE, traceId);
        }
      }
    }
  }
}
