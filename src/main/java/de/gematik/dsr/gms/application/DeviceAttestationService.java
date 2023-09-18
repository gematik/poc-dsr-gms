/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.dsr.gms.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.model.attestation.AttestationTokenPayload;
import de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter;
import de.gematik.dsr.gms.application.validation.TokenVerifier;
import de.gematik.dsr.gms.domain.DeviceAttestationSessionEntity;
import de.gematik.dsr.gms.domain.DeviceAttestationSessionKey;
import de.gematik.dsr.gms.infrastructure.DeviceAttestationSessionRepository;
import de.gematik.dsr.gms.infrastructure.DeviceRegistrationRepository;
import de.gematik.dsr.gms.web.model.DeviceAttestationRequestDTO;
import de.gematik.idp.token.JsonWebToken;
import io.vertx.core.eventbus.EventBus;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class DeviceAttestationService {

  private static final Logger LOG = Logger.getLogger(DeviceAttestationService.class);

  @Inject ClientCertificateHolder clientCertificateHolder;

  @Inject TokenVerifier tokenVerifier;

  @Inject EventBus eventBus;

  @Inject ObjectMapper objectMapper;

  @Inject NonceService nonceService;

  @Inject DeviceAttestationSessionRepository deviceAttestationSessionRepository;

  @Inject DeviceRegistrationRepository deviceRegistrationRepository;

  @ConfigProperty(
      name = "device-attestation-token.validity-time",
      defaultValue = "30") // "validity-time in minutes"
  int tokenValidityTime;

  @Transactional
  public String handleAttestationToken(final DeviceAttestationRequestDTO dto) {

    final JsonWebToken token = new JsonWebToken(dto.token());

    // 1. verify the token signature
    final X509Certificate clientCertificateFromHeader = tokenVerifier.verifyTokenSignature(token);
    if (!clientCertificateFromHeader.equals(clientCertificateHolder.getClientCertificate())) {
      throw new GMServiceRuntimeException(GMServiceExceptionReason.UNSUITABLE_CLIENT_CERTIFICATE);
    }

    // type-safe token data
    final AttestationTokenPayload attestationTokenPayload = this.obtainTokenPayload(token);

    // 2. verify nonce
    nonceService.verifyNonce(attestationTokenPayload.nonce());

    // 3. verify 'iat' (issued at) claim
    tokenVerifier.verifyTokenValidityLifetime(
        attestationTokenPayload.iat(), tokenValidityTime, ChronoUnit.MINUTES);

    // 4. check if device is known (find device registration by 'sub' claim )
    final var deviceRegistrationOptional =
        deviceRegistrationRepository.findByDeviceIdentifier(attestationTokenPayload.sub());
    if (deviceRegistrationOptional.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof("%s No device registration found by %s", traceId, attestationTokenPayload.sub());
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.DEVICE_REGISTRATION_NOT_FOUND, traceId);
    }

    // 5. check if publicKey fingerprint from mTLS is "sub" claim at DeviceAttestation token
    final byte[] clientCertPublicKeyFingerprint =
        CertificateAndKeysDataConverter.calculatePublicKeyFingerprint(
            clientCertificateHolder.getClientCertificate());
    final boolean hashesMatch =
        MessageDigest.isEqual(
            clientCertPublicKeyFingerprint,
            Base64.getDecoder().decode(attestationTokenPayload.sub()));
    if (!hashesMatch) {
      final UUID traceId = UUID.randomUUID();
      LOG.infof(
          "%s hashed public key of client certificate not equal to subject public key fingerprint",
          traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.INVALID_TOKEN, traceId);
    }

    // generate authorisation code
    final String authCode = NonceGenerator.getNonceAsHex(64);

    // store the authorisation code + code_challenge + Attestation-Token and the user_identifier
    // form the registration
    final var sessionKey =
        this.storeDeviceAttestationSession(
            authCode,
            deviceRegistrationOptional.get().getId().getUserIdentifier(),
            dto.codeChallenge(),
            dto.token());

    // publish event to trigger the DeviceToken generation asynchronously
    eventBus.publish("generate-device-token", sessionKey);

    return authCode;
  }

  private AttestationTokenPayload obtainTokenPayload(final JsonWebToken jsonWebToken) {
    return objectMapper.convertValue(jsonWebToken.getBodyClaims(), AttestationTokenPayload.class);
  }

  private DeviceAttestationSessionKey storeDeviceAttestationSession(
      final String authorisationCode,
      final String userIdentifier,
      final String codeChallenge,
      final String attestationToken) {
    final var id = new DeviceAttestationSessionKey(authorisationCode, codeChallenge);

    // persist the device attestation session
    final var session = new DeviceAttestationSessionEntity(id, userIdentifier, attestationToken);
    deviceAttestationSessionRepository.persistAndFlush(session);
    return session.getId();
  }
}
