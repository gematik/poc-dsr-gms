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

package de.gematik.dsr.gms.application.ios.receipt.validation;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.*;
import static de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter.calculatePublicKeyFingerprint;

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.receipt.IOSReceipt;
import de.gematik.dsr.gms.application.ios.receipt.IOSReceiptValidationData;
import de.gematik.dsr.gms.application.validation.CertificateChainPathValidation;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.jboss.logging.Logger;

/**
 * Read and decode the receipt bytes as a PKCS #7 container, as defined by RFC 2315. The App Store
 * encodes the payload of the container using Abstract Syntax Notation One (ASN.1), as defined by
 * ITU-T X.690. The payload contains a set of receipt attributes.
 *
 * <p>Implementation of the flow, described <a
 * href="https://developer.apple.com/documentation/appstorereceipts/validating_receipts_on_the_device#3744732">here</a>.
 *
 * @see IOSReceipt parsed and verified receipt payload.
 */
public class IOSReceiptValidation implements Validation<IOSReceiptValidationData, IOSReceipt> {

  private static final Logger LOG = Logger.getLogger(IOSReceiptValidation.class);
  private final X509Certificate rootTrustAnchor;
  private final IOSReceiptBytesToSignedDataValidation receiptToSignedDataValidation;

  private final MasterDataRepository masterDataRepository;

  private final Duration receiptMaxAge;

  private final Clock clock;

  public IOSReceiptValidation(
      final X509Certificate certificate,
      final Duration receiptMaxAge,
      final Clock clock,
      final MasterDataRepository masterDataRepository) {
    this.masterDataRepository = masterDataRepository;
    this.receiptToSignedDataValidation = new IOSReceiptBytesToSignedDataValidation();
    this.rootTrustAnchor = certificate;
    this.clock = clock;
    this.receiptMaxAge = receiptMaxAge;
  }

  @Override
  public IOSReceipt evaluate(IOSReceiptValidationData dataToValidate) {
    IOSReceiptBytesToSignedDataValidation.SignedData signedData =
        receiptToSignedDataValidation.evaluate(dataToValidate.iosReceiptData().receipt());
    verifyCertificatePath(signedData.certificateChain());
    IOSReceipt payload = signedData.payload();
    verifyAppId(payload.getAppId());
    verifyCreationDate(payload.getCreationTime(), dataToValidate.skipCreationTimeValidation());
    verifyPublicKey(payload.getAttestedCertificate(), dataToValidate.iosReceiptData().deviceKey());
    return payload;
  }

  /**
   * Evaluate the trustworthiness of the signing certificate up to the Apple public root certificate
   * for App Attest.
   *
   * @param certificates certificated chain, parsed from receipt
   */
  private void verifyCertificatePath(List<X509Certificate> certificates) {
    CertificateChainPathValidation pathValidation =
        new CertificateChainPathValidation(List.of(rootTrustAnchor), clock);
    pathValidation.evaluate(certificates);
  }

  /**
   * Verify that the receipt contains the App ID which matches available and known apps. Our app’s
   * App ID is the concatenation of your 10-digit Team ID, a period, and the app’s bundle ID.
   *
   * @param appId parsed from field 2 AppID
   * @see IOSReceipt#getAppId()
   */
  private void verifyAppId(String appId) {
    Optional<String> applicationIdSha256Hash =
        masterDataRepository.getAvailableAppIds().stream()
            .map(MasterDataRepository.AppId::buildAppId)
            .filter(id -> id.equals(appId))
            .findAny();

    if (applicationIdSha256Hash.isEmpty()) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s - Unexpected App ID: %s, AppID doesn't match to any known application ID",
          traceId, appId);
      throw new GMServiceRuntimeException(UNEXPECTED_RECEIPT_APP_ID, traceId);
    }
  }

  /**
   * Verify that the receipt’s creation time is no more than five minutes old (or any configurable
   * period). This helps to thwart replay attacks.
   *
   * @param creationTime parsed from field 12 receipt creation time.
   * @param skipCreationTimeValidation if true, skips verification
   */
  private void verifyCreationDate(Instant creationTime, boolean skipCreationTimeValidation) {
    final Instant notAfter =
        skipCreationTimeValidation ? Instant.EPOCH : Instant.now(clock).minus(receiptMaxAge);
    verifyCreationDate(creationTime, notAfter);
  }

  /**
   * Verify that the receipt’s creation time is no more than five minutes old (or any configurable
   * period). This helps to thwart replay attacks.
   *
   * @param creationTime parsed from field 12 receipt creation time.
   */
  private void verifyCreationDate(Instant creationTime, Instant notAfter) {
    if (notAfter.isAfter(creationTime)) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf("%s - Receipt creation time is after %s", traceId, notAfter);
      throw new GMServiceRuntimeException(TOO_LONG_AGO_CREATED_RECEIPT, traceId);
    }
  }

  /**
   * Verifies that the attested public key matches the one from initial attestation.
   *
   * @param attestedCertificate parsed from in field 3 certificate, encoded as a DER ASN.1 object
   * @param alreadyKnownKey initial attestation public key
   */
  private void verifyPublicKey(X509Certificate attestedCertificate, byte[] alreadyKnownKey) {
    byte[] receiptAttestedKeyBytes = calculatePublicKeyFingerprint(attestedCertificate);
    boolean hashIsEqual = MessageDigest.isEqual(receiptAttestedKeyBytes, alreadyKnownKey);
    if (!hashIsEqual) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf("%s - Public key from receipt and attestation statement doesn't match", traceId);
      throw new GMServiceRuntimeException(UNEXPECTED_RECEIPT_ATTESTED_KEY, traceId);
    }
  }
}
