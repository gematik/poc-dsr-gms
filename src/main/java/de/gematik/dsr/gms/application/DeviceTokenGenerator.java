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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.model.DeviceTokenPayload;
import de.gematik.idp.field.ClaimName;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.StringReader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import org.jose4j.keys.X509Util;

@ApplicationScoped
public class DeviceTokenGenerator {

  private static final Logger LOG = Logger.getLogger(DeviceTokenGenerator.class);

  @ConfigProperty(name = "device.token.certificate.path")
  X509Certificate certificate;

  @ConfigProperty(name = "device.token.validity", defaultValue = "60") // "validity in minutes"
  int tokenValidity;

  @ConfigProperty(name = "device.token.issuer", defaultValue = "DSR GMS 1.0.0")
  String tokenIssuer;

  @Inject ObjectMapper objectMapper;

  public String generateDeviceTokenString(
      final String subject, final DeviceTokenPayload bodyPayload) {

    LOG.infof(
        "Start generation of DeviceToken for device type %s and subject %s",
        bodyPayload.type(), subject);

    // Convert the DeviceTokenPayload POJO to JSON string
    String jsonString;
    try {
      jsonString = objectMapper.writeValueAsString(bodyPayload);
    } catch (JsonProcessingException e) {
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.INTERNAL_SERVER_ERROR,
          UUID.randomUUID(),
          "Convert DeviceTokenPayload into JSON string failed");
    }

    try (JsonReader jsonReader = Json.createReader(new StringReader(jsonString))) {
      // Create a JsonReader and convert the JSON string into a JsonObject
      JsonObject jsonObject = jsonReader.readObject();

      JwtClaimsBuilder builder = Jwt.claims(jsonObject);
      builder.issuer(tokenIssuer);
      builder.subject(subject);
      builder.issuedAt(Instant.now().getEpochSecond());
      builder.expiresAt(Instant.now().plus(tokenValidity, ChronoUnit.MINUTES));

      builder.claim(
          ClaimName.CONFIRMATION.getJoseName(), Map.of("x5t#S256", X509Util.x5tS256(certificate)));

      builder.jws().algorithm(SignatureAlgorithm.ES256);

      final String base64EncodedCertificate;
      try {
        base64EncodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new GmsCryptoException("Error while getting the encoded form of this certificate", e);
      }

      builder
          .jws()
          .header(
              ClaimName.X509_CERTIFICATE_CHAIN.getJoseName(), List.of(base64EncodedCertificate));

      final String deviceToken = builder.sign();

      LOG.infof(
          "Finish generation of DeviceToken for device type %s and subject %s",
          bodyPayload.type(), subject);

      return deviceToken;
    }
  }
}
