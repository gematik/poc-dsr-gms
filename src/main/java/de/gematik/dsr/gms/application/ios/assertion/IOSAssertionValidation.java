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

package de.gematik.dsr.gms.application.ios.assertion;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.*;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.calculatePublicKeyFingerprint;
import static de.gematik.dsr.gms.application.validation.NonceVerifier.toAttestDerivedNonce;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceExceptionReason;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.AbstractIOSValidation;
import de.gematik.dsr.gms.application.ios.AuthenticatorData;
import de.gematik.dsr.gms.application.ios.IOSValidationData;
import de.gematik.dsr.gms.application.ios.attestation.AttestationStatement;
import de.gematik.dsr.gms.application.ios.attestation.IOSAttestation;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntity;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntityIOS;
import de.gematik.dsr.gms.infrastructure.DeviceRegistrationRepository;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Provides the implementation of the assertion verification flow, described in <a
 * href="https://wiki.gematik.de/x/Tgb3Hg">DSR-RFC-02</a> - step 31, <a
 * href="https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644">
 * according to the apple documentation </a>
 */
public class IOSAssertionValidation extends AbstractIOSValidation
    implements Validation<IOSValidationData, IOSAssertionResult> {

  private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

  private final DeviceRegistrationRepository deviceRegistrationRepository;

  private final Signature signature;

  private final Predicate<Integer> counterPredicate;

  public IOSAssertionValidation(
      final Function<String, byte[]> decodingFunction,
      final MasterDataRepository masterDataRepository,
      DeviceRegistrationRepository deviceRegistrationRepository,
      Predicate<Integer> counterPredicate) {
    super(decodingFunction, masterDataRepository);
    this.deviceRegistrationRepository = deviceRegistrationRepository;
    this.signature = initSignature();
    this.counterPredicate = counterPredicate;
  }

  private Signature initSignature() {
    try {
      return Signature.getInstance(SIGNATURE_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(
          "Failed to initialize signature with algorithm: " + SIGNATURE_ALGORITHM, e);
    }
  }

  @Override
  public IOSAssertionResult evaluate(IOSValidationData dataToValidate) {
    byte[] decoded = decodingFunction.apply(dataToValidate.currentData());
    try {
      IOSAssertion iosAssertion = cborObjectMapper.readValue(decoded, IOSAssertion.class);
      PublicKey registeredPublicKey = getRegisteredPublicKey(dataToValidate.sub());
      byte[] generatedChallenge = generateChallenge(dataToValidate.nonce(), dataToValidate.sub());
      AuthenticatorData authenticatorData =
          verifyAssertion(iosAssertion, generatedChallenge, registeredPublicKey);
      return new IOSAssertionResult(
          authenticatorData, calculatePublicKeyFingerprint(registeredPublicKey));
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      logger.errorf("%s Error while parsing assertion statement. Invalid CBOR format", traceId, e);
      throw new GMServiceRuntimeException(INVALID_CBOR_FORMAT, traceId, e);
    }
  }

  /**
   * Workflow implementation described <a
   * href="https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644">
   * here </a> Points 1 - 6
   *
   * @param iosAssertion from assertion String parsed {@link IOSAssertion}
   * @param generatedChallenge nonce plus public_mTLS_key byte array
   * @param registeredPublicKey registered credCertificate public key saved in the database and
   *     recreated from attestation String corresponding to registered public_mTLS_key
   * @return parsed from authData bytes {@link AuthenticatorData}
   * @see IOSAssertion#authenticatorData()
   */
  protected AuthenticatorData verifyAssertion(
      final IOSAssertion iosAssertion,
      byte[] generatedChallenge,
      final PublicKey registeredPublicKey) {
    AuthenticatorData authenticatorData = new AuthenticatorData(iosAssertion.authenticatorData());
    verifyRpId(authenticatorData.getRpId());
    verifyCounter(authenticatorData.getCounter());
    byte[] clientDataHash =
        generateClientDataHash(iosAssertion.authenticatorData(), generatedChallenge);
    verifySignature(clientDataHash, iosAssertion.signature(), registeredPublicKey);
    return authenticatorData;
  }

  private void verifySignature(
      byte[] clientDataHash, byte[] signatureBytes, PublicKey registeredPublicKey) {
    try {
      signature.initVerify(registeredPublicKey);
      signature.update(clientDataHash);
      boolean isCorrect = signature.verify(signatureBytes);
      if (!isCorrect) {
        throw new GMServiceRuntimeException(INVALID_SIGNATURE_FOR_NONCE, UUID.randomUUID());
      }
    } catch (InvalidKeyException | SignatureException e) {
      throw new GMServiceRuntimeException(UNSUITABLE_KEY_FOR_SIGNATURE, UUID.randomUUID(), e);
    }
  }

  protected PublicKey getRegisteredPublicKey(final String devicePublicMTLSKey) {
    Optional<DeviceRegistrationEntity> deviceIdentifier =
        deviceRegistrationRepository.findByDeviceIdentifier(devicePublicMTLSKey);
    return deviceIdentifier
        .map(DeviceRegistrationEntityIOS.class::cast)
        .map(DeviceRegistrationEntityIOS::getAttestation)
        .map(decodingFunction::apply)
        .map(
            bytes -> {
              try {
                return cborObjectMapper.readValue(bytes, IOSAttestation.class);
              } catch (IOException e) {
                throw new GMServiceRuntimeException(INVALID_CBOR_FORMAT, UUID.randomUUID(), e);
              }
            })
        .map(IOSAttestation::attStmt)
        .map(AttestationStatement::parsedX509Certificates)
        .map(l -> l.get(0))
        .map(X509Certificate::getPublicKey)
        .orElseThrow(
            () ->
                new GMServiceRuntimeException(
                    GMServiceExceptionReason.DEVICE_REGISTRATION_NOT_FOUND, UUID.randomUUID()));
  }

  @Override
  protected Predicate<Integer> counterPredicate() {
    return counterPredicate;
  }

  @Override
  protected byte[] toNonceByteArray(String nonce) {
    return toAttestDerivedNonce(nonce, decodingFunction);
  }
}
