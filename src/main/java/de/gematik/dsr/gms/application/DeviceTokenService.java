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

package de.gematik.dsr.gms.application;

import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.infrastructure.DeviceAttestationSessionRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.jboss.logging.Logger;

@ApplicationScoped
public class DeviceTokenService {

  private static final Logger LOG = Logger.getLogger(DeviceTokenService.class);

  @Inject DeviceAttestationSessionRepository deviceAttestationSessionRepository;

  public Optional<String> obtainDeviceToken(final String authCode, final String codeVerifier) {

    // 1. build code challenge with given code verifier for comparison
    // Note: code challenge method is always S256)
    final var codeChallenge = buildCodeChallenge(codeVerifier);

    // 2. check, does device attestation session exists
    final var sessionEntityOptional =
        deviceAttestationSessionRepository.findByAuthCodeAndCodeChallenge(authCode, codeChallenge);
    if (sessionEntityOptional.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof(
          "%s - No DeviceAttestation-Session found with authorization code '%s' and code challenge"
              + " '%s'",
          traceId, authCode, codeVerifier);
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.DEVICE_ATTESTATION_SESSION_NOT_FOUND, traceId);
    }

    // TODO: klären, was erhält der Aufrufer wenn die asynchrone Erzeugung des DeviceToken
    // fehlschlägt
    return Optional.ofNullable(sessionEntityOptional.get().getDeviceToken());
  }

  /*
  code_challenge — The code challenge is created by SHA256 hashing the code_verifier
  and base64 URL encoding the resulting hash Base64UrlEncode(SHA256Hash(code_verifier)).
   */
  private static String buildCodeChallenge(final String codeVerifier) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(codeVerifier.getBytes());
      final var encoder = Base64.getUrlEncoder().withoutPadding();
      return encoder.encodeToString(hash);
    } catch (NoSuchAlgorithmException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s %s", traceId, e.getLocalizedMessage());
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.INTERNAL_SERVER_ERROR, traceId, e);
    }
  }
}
