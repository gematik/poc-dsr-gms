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

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.model.DeviceAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceTokenPayload;
import de.gematik.dsr.gms.application.model.DeviceType;
import de.gematik.dsr.gms.application.model.attestation.AttestationTokenPayload;
import de.gematik.dsr.gms.domain.DeviceAttestationSessionKey;
import de.gematik.dsr.gms.infrastructure.DeviceAttestationSessionRepository;
import de.gematik.idp.token.JsonWebToken;
import io.quarkus.arc.All;
import io.quarkus.vertx.ConsumeEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class DeviceTokenProcess {

  private static final Logger LOG = Logger.getLogger(DeviceTokenProcess.class);

  @Inject ObjectMapper objectMapper;

  @Inject DeviceAttestationSessionRepository deviceAttestationSessionRepository;

  @Inject DeviceTokenGenerator deviceTokenGenerator;

  @Inject @All List<DeviceAttestation> deviceAttestations;

  // we use the validity of the token also as the validity of device attestation session,
  // once a token is generated
  @ConfigProperty(name = "device.token.validity", defaultValue = "60") // "validity in minutes"
  int tokenValidity;

  @ConsumeEvent(value = "generate-device-token", blocking = true)
  @Transactional
  public void process(final DeviceAttestationSessionKey sessionKey) {
    LOG.infof("Start DeviceToken-Generator process for %s", sessionKey);
    final var sessionEntityOptional =
        deviceAttestationSessionRepository.findByAuthCodeAndCodeChallenge(
            sessionKey.getAuthorisationCode(), sessionKey.getCodeChallenge());
    if (sessionEntityOptional.isEmpty()) {
      LOG.infof(
          "DeviceAttestationSessionEntity not found by authCode '%s' and codeChallenge '%s'",
          sessionKey.getAuthorisationCode(), sessionKey.getCodeChallenge());
      return;
    }

    final var session = sessionEntityOptional.get();

    // type-safe attestation token payload
    AttestationTokenPayload attestationTokenPayload =
        this.obtainTokenPayload(session.getAttestationToken());

    final DeviceAttestationResult<AttestationTokenPayload> attested =
        attest(attestationTokenPayload);

    final DeviceTokenPayload tokenPayload =
        new DeviceTokenPayload(
            attestationTokenPayload.type(),
            session.getUserIdentifier(),
            attested.deviceHealthMap());

    // generate the device token
    final String deviceTokenRawString =
        deviceTokenGenerator.generateDeviceTokenString(attestationTokenPayload.sub(), tokenPayload);

    // store the DeviceToken at device attestation session
    session.setDeviceToken(deviceTokenRawString, OffsetDateTime.now().plusMinutes(tokenValidity));
    deviceAttestationSessionRepository.persistAndFlush(session);
  }

  private AttestationTokenPayload obtainTokenPayload(final String attestationTokenRawString) {
    final var jsonWebToken = new JsonWebToken(attestationTokenRawString);
    return objectMapper.convertValue(jsonWebToken.getBodyClaims(), AttestationTokenPayload.class);
  }

  private DeviceAttestationResult<AttestationTokenPayload> attest(
      AttestationTokenPayload attestationTokenPayload) {
    DeviceType type = attestationTokenPayload.type();
    return deviceAttestations.stream()
        .filter(deviceAttestation -> deviceAttestation.getType().equals(type))
        .findAny()
        .map(deviceAttestation -> deviceAttestation.attestation(attestationTokenPayload))
        .orElseThrow(
            () ->
                new GMServiceRuntimeException(
                    GMServiceExceptionReason.UNKNOWN_DEVICE_TYPE, UUID.randomUUID()));
  }
}
