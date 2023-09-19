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

package de.gematik.dsr.gms.application.validation;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.token.JsonWebToken;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.jboss.logging.Logger;

@ApplicationScoped
public class TokenVerifier {

  private static final Logger LOG = Logger.getLogger(TokenVerifier.class);

  private static final String ISSUER_PREFIX = "TrustSDK_";

  @Inject MasterDataRepository masterDataRepository;

  /**
   * @param token The Json Web Token to verify
   * @return The client certificate from header
   */
  public X509Certificate verifyTokenSignature(final JsonWebToken token) {
    try {
      // obtain Public-Key from x5c Header
      final Optional<X509Certificate> clientCertificateFromHeader =
          token.getClientCertificateFromHeader();
      if (clientCertificateFromHeader.isPresent()) {
        X509Certificate clientCertificate = clientCertificateFromHeader.get();
        // verify Device Registration Token
        token.verify(clientCertificate.getPublicKey());
        return clientCertificate;
      } else {
        final UUID traceId = UUID.randomUUID();
        LOG.infof("%s Missing 'x5c' claim at token header", traceId);
        throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN_SYNTAX, traceId);
      }
    } catch (IdpJoseException | IdpCryptoException e) {
      final UUID traceId = UUID.randomUUID();
      if (e instanceof IdpJoseException joseException) {
        LOG.infof("%s %s", traceId, joseException.getMessageForUntrustedClients());
      } else {
        LOG.infof("%s %s", traceId, e.getLocalizedMessage());
      }
      throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN, traceId);
    }
  }

  public void verifyTokenValidityLifetime(
      final Long iat, final int tokenValidityMinutes, final TemporalUnit unit) {
    if (Objects.isNull(iat)) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Invalid token, 'iat' is null", traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN_SYNTAX, traceId);
    }
    final Instant tokenValidityUntil = Instant.ofEpochSecond(iat).plus(tokenValidityMinutes, unit);

    if (tokenValidityUntil.isBefore(Instant.now())) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Token is expired on %s", traceId, tokenValidityUntil);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.TOKEN_EXPIRED, traceId);
    }
  }

  public void verifyTokenIssuer(final String issuer) {
    if (issuer == null || !issuer.startsWith(ISSUER_PREFIX)) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Invalid issuer %s", traceId, issuer);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN_ISSUER, traceId);
    }
    String version = issuer.substring(ISSUER_PREFIX.length());
    List<String> trustedSDKVersions = masterDataRepository.getAvailableTrustedSDKVersions();
    if (!trustedSDKVersions.contains(version)) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s Unsupported issuer version %s", traceId, version);
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.UNSUPPORTED_ISSUER_VERSION, traceId);
    }
  }
}
