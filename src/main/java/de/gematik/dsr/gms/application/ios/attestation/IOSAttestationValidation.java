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

package de.gematik.dsr.gms.application.ios.attestation;

import static de.gematik.dsr.gms.application.Validation.ValidationExceptionReason.INVALID_ROOT_CERTIFICATE;
import static de.gematik.dsr.gms.application.ios.IOSValidationReason.*;
import static de.gematik.dsr.gms.application.util.ByteArrayHelper.concatArrays;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.calculatePublicKeyFingerprint;
import static de.gematik.dsr.gms.application.validation.NonceVerifier.toIntegrityNonce;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.AbstractIOSValidation;
import de.gematik.dsr.gms.application.ios.AuthenticatorData;
import de.gematik.dsr.gms.application.ios.IOSValidationData;
import de.gematik.dsr.gms.application.validation.CertificateChainPathValidation;
import de.gematik.dsr.gms.application.validation.CertificateChainValidation;
import de.gematik.dsr.gms.application.validation.CertificateExtensionParsingValidation;
import de.gematik.dsr.gms.application.validation.NonceVerifier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLTaggedObject;

/**
 * Provides the implementation of the attestation verification flow <a
 * href="https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643">
 * according to the apple documentation </a>
 */
public class IOSAttestationValidation extends AbstractIOSValidation
    implements Validation<IOSValidationData, IOSAttestationResult> {

  private static final String APPLE_KEY_NONCE_OID = "1.2.840.113635.100.8.2";

  private final CertificateChainValidation certificateChainValidation;

  private final CertificateExtensionParsingValidation certificateExtensionParsingValidation;

  private final CertificateChainPathValidation certificateChainPathValidation;

  public IOSAttestationValidation(
      final X509Certificate certificate,
      final Function<String, byte[]> decodingFunction,
      final Clock clock,
      final MasterDataRepository masterDataRepository) {
    super(decodingFunction, masterDataRepository);
    this.certificateChainValidation = initCertificateChainValidation(certificate, clock);
    this.certificateExtensionParsingValidation =
        new CertificateExtensionParsingValidation(APPLE_KEY_NONCE_OID);
    this.certificateChainPathValidation =
        new CertificateChainPathValidation(List.of(certificate), clock);
  }

  private CertificateChainValidation initCertificateChainValidation(
      X509Certificate certificate, Clock clock) {
    return new CertificateChainValidation(
        certificate,
        c -> {
          if (c.getVersion() != certificate.getVersion()) {
            throw new GMServiceRuntimeException(INVALID_ROOT_CERTIFICATE);
          }
          return c;
        },
        clock);
  }

  @Override
  public IOSAttestationResult evaluate(IOSValidationData dataToValidate) {
    byte[] decoded = decodingFunction.apply(dataToValidate.currentData());
    try {
      IOSAttestation iosAttestation = cborObjectMapper.readValue(decoded, IOSAttestation.class);

      verifyFormatIdentifier(iosAttestation.fmt());

      AttestationStatement attStmt = iosAttestation.attStmt();
      List<X509Certificate> x509Certificates =
          certificateChainValidation.evaluate(attStmt.parsedX509Certificates());
      x509Certificates = certificateChainPathValidation.evaluate(x509Certificates);

      byte[] challenge = generateChallenge(dataToValidate.nonce(), dataToValidate.sub());
      verifyNonce(iosAttestation.authData(), challenge, x509Certificates);

      byte[] deviceFingerprint = calculatePublicKeyFingerprint(x509Certificates.get(0));
      final AuthenticatorData authenticatorData =
          verifyAttestedCredentialData(iosAttestation.authData(), deviceFingerprint);
      if (!dataToValidate.keyIdentifierPredicate().test(deviceFingerprint)) {
        final UUID traceId = UUID.randomUUID();
        logger.errorf("%s Key identifier doesn't match to attestation data", traceId);
        throw new GMServiceRuntimeException(INVALID_KEY_ID, traceId);
      }
      return new IOSAttestationResult(
          deviceFingerprint, attStmt.receipt(), authenticatorData.getCounter());
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      logger.errorf(
          "%s Error while parsing attestation statement. Invalid CBOR format", traceId, e);
      throw new GMServiceRuntimeException(INVALID_CBOR_FORMAT, traceId, e);
    }
  }

  private void verifyFormatIdentifier(String fmt) {
    if (!IOSAttestation.FORMAT_IDENTIFIER.equals(fmt)) {
      final UUID traceId = UUID.randomUUID();
      logger.errorf(
          "%s Invalid format identifier. Expected %s, but was %s",
          traceId, IOSAttestation.FORMAT_IDENTIFIER, fmt);
      throw new GMServiceRuntimeException(INVALID_FORMAT_IDENTIFIER, traceId);
    }
  }

  /**
   * Workflow implementation described here -
   * https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643
   * Points 2 - 9
   *
   * @param authData authenticator data
   * @param deviceFingerprint fingerprint von the credCertificate public key
   * @return parsed data, if they were valid
   */
  protected AuthenticatorData verifyAttestedCredentialData(
      byte[] authData, byte[] deviceFingerprint) {
    AuthenticatorData authenticatorData = new AuthenticatorData(authData);
    verifyRpId(authenticatorData.getRpId());
    verifyCounter(authenticatorData.getCounter());
    if (AuthenticatorData.AuthenticatorDataFlag.AT.equals(authenticatorData.getFlags())) {
      AuthenticatorData.AttestedCredentialData attestedCredentialData =
          authenticatorData.getAttestedCredentialData();
      verifyCredentialId(deviceFingerprint, attestedCredentialData.credentialId());
      verifyAuguid(attestedCredentialData.aaguid());
    } else {
      UUID traceId = UUID.randomUUID();
      logger.errorf("%s Unexpected authData flags byte - should be %d", traceId, 0x40);
      throw new GMServiceRuntimeException(UNEXPECTED_ATTESTATION_FLAGS, traceId);
    }
    return authenticatorData;
  }

  @Override
  protected Predicate<Integer> counterPredicate() {
    return c -> c == 0;
  }

  /**
   * Point 2, 3 and 4
   *
   * <p>Create clientDataHash as the SHA256 hash of the one-time challenge your server sends to your
   * app before performing the attestation, and append that hash to the end of the authenticator
   * data (authData from the decoded object).
   *
   * <p>Generate a new SHA256 hash of the composite item to create nonce.
   *
   * <p>Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, which is a
   * DER-encoded ASN.1 sequence. Decode the sequence and extract the single octet string that it
   * contains. Verify that the string equals nonce.
   *
   * @param authData authData from the decoded object
   * @param challenge obtained challenge
   * @param x509Certificates certificates parsed from x5c field
   */
  protected void verifyNonce(
      byte[] authData, byte[] challenge, List<X509Certificate> x509Certificates) {
    byte[] clientDataHash = generateClientDataHash(authData, challenge);
    byte[] decodedNonce = extractNonce(x509Certificates);
    NonceVerifier.verifyNonce(clientDataHash, decodedNonce);
  }

  @Override
  protected byte[] toNonceByteArray(String nonce) {
    return toIntegrityNonce(nonce, decodingFunction);
  }

  protected byte[] extractNonce(List<X509Certificate> x509Certificates) {
    ASN1Sequence asn1Sequence = certificateExtensionParsingValidation.evaluate(x509Certificates);
    return Optional.ofNullable(asn1Sequence.getObjectAt(0))
        .map(DLTaggedObject.class::cast)
        .map(DLTaggedObject::getBaseObject)
        .map(DEROctetString.class::cast)
        .map(DEROctetString::getOctets)
        .orElseThrow(
            () -> new GMServiceRuntimeException(NOT_PARSABLE_NONCE_SEQUENCE, UUID.randomUUID()));
  }

  /**
   * Point 5 and 9 Create the SHA256 hash of the public key in credCert, and verify that it matches
   * the key identifier from your app. Verify that the authenticator data’s credentialId field is
   * the same as the key identifier.
   *
   * @param deviceFingerprint SHA256 hash of the public key in credCert
   * @param credentialId credentialId field
   */
  private void verifyCredentialId(byte[] deviceFingerprint, byte[] credentialId) {
    if (!MessageDigest.isEqual(deviceFingerprint, credentialId)) {
      UUID traceId = UUID.randomUUID();
      logger.errorf("%s Credential ID doesn't match app key identifier", traceId);
      throw new GMServiceRuntimeException(INVALID_RP_ID, traceId);
    }
  }

  /**
   * Point 8 Verify that the authenticator data’s aaguid field is either appattestdevelop if
   * operating in the development environment, or appattest followed by seven 0x00 bytes if
   * operating in the production environment.
   *
   * @param aaguid data to verify
   */
  protected void verifyAuguid(byte[] aaguid) {
    byte[] develop = "appattestdevelop".getBytes(StandardCharsets.UTF_8);
    byte[] production =
        concatArrays(
            "appattest".getBytes(StandardCharsets.UTF_8),
            new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    if (!Arrays.equals(aaguid, develop) && !Arrays.equals(aaguid, production)) {
      UUID traceId = UUID.randomUUID();
      logger.errorf("%s Invalid aaguid field value", traceId);
      throw new GMServiceRuntimeException(UNEXPECTED_AAGUID_FIELD, traceId);
    }
  }
}
