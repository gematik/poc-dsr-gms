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

import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.calculatePublicKeyFingerprint;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.IOSDeviceAttestation;
import de.gematik.dsr.gms.application.ios.attestation.IOSAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceAttestationResult;
import de.gematik.dsr.gms.application.model.DeviceType;
import de.gematik.dsr.gms.application.model.registration.AndroidRegistrationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.IOSRegistrationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.RegistrationTokenPayload;
import de.gematik.dsr.gms.application.util.CSRDataConverter;
import de.gematik.dsr.gms.application.validation.NonceVerifier;
import de.gematik.dsr.gms.application.validation.TokenVerifier;
import de.gematik.dsr.gms.domain.DeviceIdentificationKey;
import de.gematik.dsr.gms.domain.DeviceReceiptEntityIOS;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntityAndroid;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntityIOS;
import de.gematik.dsr.gms.infrastructure.DeviceReceiptRepository;
import de.gematik.dsr.gms.infrastructure.DeviceRegistrationRepository;
import de.gematik.idp.token.JsonWebToken;
import io.quarkus.arc.All;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class RegisterDeviceService {

  private static final Logger LOG = Logger.getLogger(RegisterDeviceService.class);

  @Inject TokenVerifier tokenVerifier;

  @Inject ObjectMapper objectMapper;

  @Inject NonceService nonceService;

  @Inject DeviceSecurityRatingCA ca;

  @Inject DeviceRegistrationRepository deviceRegistrationRepository;

  @Inject DeviceReceiptRepository deviceReceiptRepository;

  @Inject @All List<DeviceAttestation> deviceAttestations;

  @ConfigProperty(
      name = "device-registration-token.validity-time",
      defaultValue = "60") // "validity-time in minutes"
  int tokenValidityTime;

  @Transactional
  public String registerDevice(final String jws) {

    final JsonWebToken token = new JsonWebToken(jws);

    // 1. verify the token signature
    final var clientCertificate = tokenVerifier.verifyTokenSignature(token);

    // type-safe token data
    final RegistrationTokenPayload registrationTokenPayload = this.obtainTokenPayload(token);

    // 2. verify nonce
    nonceService.verifyNonce(registrationTokenPayload.nonce());

    // 3. verify 'iat' (issued at) claim
    tokenVerifier.verifyTokenValidityLifetime(
        registrationTokenPayload.iat(), tokenValidityTime, ChronoUnit.MINUTES);

    // 4. verify 'iss' claim
    tokenVerifier.verifyTokenIssuer(registrationTokenPayload.iss());

    // 5. verify device and device keys
    DeviceAttestationResult<RegistrationTokenPayload> deviceAttestationResult =
        attest(registrationTokenPayload);

    // verify CSR
    verifyCSR(
        registrationTokenPayload.csr(),
        registrationTokenPayload.sub(),
        registrationTokenPayload.nonce());

    // issue the CSR at our temp. CA
    final String certificateEncoded = ca.issueCertificate(registrationTokenPayload.csr());

    // extract KV-Nummer (user identity) from EF.C.CH.AUT.E256
    final String userIdentity = extractUserIdentity(clientCertificate);
    LOG.infof("KV-Nummer '%s' found.", userIdentity);

    // store the registration
    this.storeDeviceRegistration(
        registrationTokenPayload.sub(), userIdentity, deviceAttestationResult);

    return certificateEncoded;
  }

  private RegistrationTokenPayload obtainTokenPayload(final JsonWebToken jsonWebToken) {
    return objectMapper.convertValue(jsonWebToken.getBodyClaims(), RegistrationTokenPayload.class);
  }

  static String extractUserIdentity(X509Certificate certificate) {
    try {
      X500Name subject = new JcaX509CertificateHolder(certificate).getSubject();
      final RDN[] ouArray = subject.getRDNs(BCStyle.OU);

      Optional<String> optionalUserIdentity =
          Arrays.stream(ouArray)
              .map(ou -> IETFUtils.valueToString(ou.getFirst().getValue()))
              .filter(s -> Character.isLetter(s.charAt(0)))
              .findFirst();

      if (optionalUserIdentity.isPresent()) {
        return optionalUserIdentity.get();
      } else {
        UUID traceId = UUID.randomUUID();
        LOG.infof("%s No user identity found at certificate attribut OU.", traceId);
        throw new GMServiceRuntimeException(
            GMServiceExceptionReason.MISSING_USER_IDENTITY,
            traceId,
            "Unable to extract user identity from certificate - missing suitable attribut.");
      }
    } catch (CertificateEncodingException e) {
      throw new GMServiceRuntimeException(
          GMServiceExceptionReason.CERTIFICATE_ENCODING_PROBLEM, UUID.randomUUID(), e);
    }
  }

  private void storeDeviceRegistration(
      final String deviceIdentifier,
      final String userIdentifier,
      final DeviceAttestationResult<RegistrationTokenPayload> deviceAttestationResult) {

    final var id = new DeviceIdentificationKey(userIdentifier, deviceIdentifier);
    final RegistrationTokenPayload registrationTokenPayload =
        deviceAttestationResult.getOriginalPayload();

    // 1. check, if device already registered for user identity
    final var entity = deviceRegistrationRepository.findByIdOptional(id);
    if (entity.isPresent()) {
      throw new GMServiceRuntimeException(GMServiceExceptionReason.DEVICE_ALREADY_REGISTERED);
    }
    // 2. persist the device registration
    if (DeviceType.ANDROID == registrationTokenPayload.type()) {
      final var androidRegistrationTokenPayload =
          (AndroidRegistrationTokenPayload) registrationTokenPayload;
      final var deviceRegistrationEntityAndroid =
          new DeviceRegistrationEntityAndroid(
              id, androidRegistrationTokenPayload.attestCertChain().get(0));
      deviceRegistrationRepository.persistAndFlush(deviceRegistrationEntityAndroid);
      return;
    }
    if (DeviceType.IOS == registrationTokenPayload.type()) {
      final var iosRegistrationTokenPayload =
          (IOSRegistrationTokenPayload) registrationTokenPayload;
      final var deviceRegistrationEntityIOS =
          new DeviceRegistrationEntityIOS(id, iosRegistrationTokenPayload.attestation());
      deviceRegistrationRepository.persistAndFlush(deviceRegistrationEntityIOS);

      final IOSAttestationResult result =
          ((IOSDeviceAttestation.IOSDeviceRegistrationResult) deviceAttestationResult)
              .attestationResult();
      final DeviceReceiptEntityIOS receiptEntityIOS =
          new DeviceReceiptEntityIOS(
              deviceRegistrationEntityIOS.getId(),
              Base64.getEncoder().withoutPadding().encodeToString(result.receipt()),
              result.counter());
      deviceReceiptRepository.persistAndFlush(receiptEntityIOS);
    }
  }

  /**
   * @param csrEncoded CSR base64 encoded DER
   * @param subjectPublicKeyFingerprint Hex-encoded SHA-256
   */
  static void verifyCSR(
      final String csrEncoded, final String subjectPublicKeyFingerprint, final String nonce) {

    // convert CSR from DER format
    final PKCS10CertificationRequest csr =
        CSRDataConverter.convertEncodedCsrToPKCS10PKCS10CertificationRequest(csrEncoded);

    // extract public key bytes from CSR
    SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();

    // build SHA256 of public key from CSR
    final byte[] publicKeyHash = calculatePublicKeyFingerprint(subjectPublicKeyInfo);

    // compare hash values
    final boolean hashesMatch =
        MessageDigest.isEqual(
            publicKeyHash, Base64.getDecoder().decode(subjectPublicKeyFingerprint));

    if (!hashesMatch) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s hashed public key of CSR not equal to subject public key fingerprint", traceId);
      throw new GMServiceRuntimeException(GMServiceExceptionReason.CSR_INVALID, traceId);
    }

    // verify tte nonce at the CSR - OID '1.2.840.113549.1.9.7'
    final byte[] nonceFromCSR = CSRDataConverter.extractNonceFromCSR(csr);
    NonceVerifier.verifyCSRMTLSNonce(nonce, nonceFromCSR);
  }

  private DeviceAttestationResult<RegistrationTokenPayload> attest(
      RegistrationTokenPayload registrationTokenPayload) {
    DeviceType type = registrationTokenPayload.type();
    return deviceAttestations.stream()
        .filter(deviceAttestation -> deviceAttestation.getType().equals(type))
        .findAny()
        .map(deviceAttestation -> deviceAttestation.registration(registrationTokenPayload))
        .orElseThrow(
            () ->
                new GMServiceRuntimeException(
                    GMServiceExceptionReason.UNKNOWN_DEVICE_TYPE, UUID.randomUUID()));
  }
}
