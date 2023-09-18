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

package de.gematik.dsr.gms.application.android.attestcertchain.validation;

import static de.gematik.dsr.gms.application.Validation.ValidationExceptionReason.INVALID_ROOT_CERTIFICATE;
import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyDescription.createAttestationKeyDescription;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.calculatePublicKeyFingerprint;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.loadCertificates;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyDescription;
import de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyExceptionReason;
import de.gematik.dsr.gms.application.android.attestcertchain.AttestationResult;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.model.attestation.AndroidAttestationTokenPayload;
import de.gematik.dsr.gms.application.model.registration.AndroidRegistrationTokenPayload;
import de.gematik.dsr.gms.application.util.SystemClockProvider;
import de.gematik.dsr.gms.application.validation.CertificateChainPathValidation;
import de.gematik.dsr.gms.application.validation.CertificateChainValidation;
import de.gematik.dsr.gms.application.validation.CertificateDecryptValidation;
import de.gematik.dsr.gms.application.validation.CertificateExtensionParsingValidation;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;

/**
 * Validation Bean for 'attestCertChain' Field from the token payloads. Provides chain of validation
 * steps, each is depending on previous result.
 */
@ApplicationScoped
public class AttestCertChainValidation
    implements Validation<AttestCertChainValidation.AttestCertChainData, AttestationResult> {

  private static final String GOOGLE_KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

  private final CertificateDecryptValidation certificateDecryptValidation;
  private final CertificateChainValidation certificateChainValidation;
  private final GoogleRevokeListValidation googleRevokeListValidation;
  private final CertificateExtensionParsingValidation certificateExtensionParsingValidation;
  private final CertificateChainPathValidation certificateChainPathValidation;

  @Inject
  public AttestCertChainValidation(
      @ConfigProperty(name = "android.public-key-path") final PublicKey googleRootPublicKey,
      @ConfigProperty(name = "android.root-certificates") String[] googleRootCertificatePaths,
      @RestClient GoogleRevokeListValidation.GoogleRevokeListRestClient revokeListRestClient,
      SystemClockProvider systemClockProvider) {
    this.certificateChainValidation =
        new CertificateChainValidation(
            googleRootPublicKey,
            c -> {
              if (!MessageDigest.isEqual(
                  c.getPublicKey().getEncoded(), googleRootPublicKey.getEncoded())) {
                throw new GMServiceRuntimeException(INVALID_ROOT_CERTIFICATE);
              }
              return c;
            },
            systemClockProvider.systemClock());
    this.certificateDecryptValidation = new CertificateDecryptValidation();
    this.googleRevokeListValidation = new GoogleRevokeListValidation(revokeListRestClient);
    this.certificateExtensionParsingValidation =
        new CertificateExtensionParsingValidation(GOOGLE_KEY_DESCRIPTION_OID);

    List<X509Certificate> googleRootCAs = loadCertificates(googleRootCertificatePaths);
    this.certificateChainPathValidation =
        new CertificateChainPathValidation(googleRootCAs, systemClockProvider.systemClock());
  }

  @Override
  public AttestationResult evaluate(AttestCertChainData dataToValidate) {
    List<X509Certificate> chainVerified =
        certificateDecryptValidation.evaluate(dataToValidate.attestCertChain());
    chainVerified = certificateChainValidation.evaluate(chainVerified);
    chainVerified = certificateChainPathValidation.evaluate(chainVerified);
    chainVerified = googleRevokeListValidation.evaluate(chainVerified);
    final ASN1Sequence asn1Sequence = certificateExtensionParsingValidation.evaluate(chainVerified);

    final AttestationKeyDescription attestationKeyDescription =
        createAttestationKeyDescription(asn1Sequence);
    if (dataToValidate.validateSecurityLevel()) {
      verifySecurityLevel(attestationKeyDescription);
    }
    // Compare extracted nonce to original
    dataToValidate.challengeVerifier().accept(attestationKeyDescription.getAttestationChallenge());

    final byte[] thumbprint = calculatePublicKeyFingerprint(chainVerified.get(0));
    // compare hash values sub and public key fingerprint of leaf certificate.
    dataToValidate.deviceFingerprintVerifier.accept(thumbprint);
    return new AttestationResult(thumbprint, attestationKeyDescription);
  }

  private void verifySecurityLevel(AttestationKeyDescription attestationKeyDescription) {
    AttestationKeyDescription.SecurityLevel securityLevel =
        attestationKeyDescription.getAttestationSecurityLevel();
    if (!AttestationKeyDescription.SecurityLevel.appreciatedSecurityLevels()
        .contains(securityLevel)) {
      throw new GMServiceRuntimeException(
          AttestationKeyExceptionReason.INVALID_ATTESTATION_SECURITY_LEVEL, UUID.randomUUID());
    }
  }

  /**
   * Contains data needed for the attestation of the payload part: 'attestCertChain'
   *
   * @param attestCertChain List with certificate chain as Base64 encoded strings
   * @param challengeVerifier function for nonce and extracted challenge verification, depends on
   *     flow
   * @param deviceFingerprintVerifier function for leaf certificate public key verification, depends
   *     on flow
   * @param validateSecurityLevel flag to tur on or off the {@link
   *     de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyDescription.SecurityLevel}
   *     check
   * @see AndroidRegistrationTokenPayload#attestCertChain()
   * @see AndroidAttestationTokenPayload#attestCertChain()
   */
  public record AttestCertChainData(
      List<String> attestCertChain,
      Consumer<byte[]> challengeVerifier,
      Consumer<byte[]> deviceFingerprintVerifier,
      boolean validateSecurityLevel) {}
}
