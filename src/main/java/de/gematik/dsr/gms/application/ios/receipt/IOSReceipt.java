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

package de.gematik.dsr.gms.application.ios.receipt;

import static de.gematik.dsr.gms.application.ios.receipt.IOSReceiptAttribute.*;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

/**
 * The App Attest receipt has a structure similar to an App Store receipt, with a PKCS #7 container
 * that contains a signature, certificate chain, and an ASN.1–encoded payload. This class provides
 * the Payload of the App Attest receipt.
 *
 * <p>App Attest receipts use the following fields: @see {@link IOSReceiptAttribute}
 *
 * <p>Each receipt attribute contains a type, a version, and a value. The App Store defines the
 * structure of the payload with the following ASN.1 notation: <code>
 * ReceiptModule DEFINITIONS ::=
 * BEGIN
 *
 *
 * ReceiptAttribute ::= SEQUENCE {
 *     type    INTEGER,
 *     version INTEGER,
 *     value   OCTET STRING
 * }
 *
 * Payload ::= SET OF ReceiptAttribute
 *
 * END
 * </code>
 */
public class IOSReceipt {
  private final String appId;
  private final X509Certificate attestedCertificate;

  private final byte[] clientHash;

  private final String token;

  private final IOSReceiptType receiptType;

  private final Instant creationTime;

  private final Instant expirationTime;

  private Integer riskMetric;

  private Instant notBefore;

  private IOSReceipt(final Map<IOSReceiptAttribute, byte[]> receiptAttributeMap) {
    this.appId = (String) APP_ID.getConvertedValue(receiptAttributeMap.get(APP_ID));
    this.attestedCertificate =
        (X509Certificate)
            ATTESTED_PUBLIC_KEY.getConvertedValue(receiptAttributeMap.get(ATTESTED_PUBLIC_KEY));
    this.clientHash = (byte[]) CLIENT_HASH.getConvertedValue(receiptAttributeMap.get(CLIENT_HASH));
    this.token = (String) TOKEN.getConvertedValue(receiptAttributeMap.get(TOKEN));
    this.receiptType =
        (IOSReceiptType) RECEIPT_TYPE.getConvertedValue(receiptAttributeMap.get(RECEIPT_TYPE));
    this.creationTime =
        (Instant) CREATION_TIME.getConvertedValue(receiptAttributeMap.get(CREATION_TIME));
    this.expirationTime =
        (Instant) EXPIRATION_TIME.getConvertedValue(receiptAttributeMap.get(EXPIRATION_TIME));
    if (IOSReceiptType.RECEIPT.equals(receiptType)) {
      this.riskMetric =
          (Integer) RISK_METRIC.getConvertedValue(receiptAttributeMap.get(RISK_METRIC));
      this.notBefore = (Instant) NOT_BEFORE.getConvertedValue(receiptAttributeMap.get(NOT_BEFORE));
    }
  }

  public String getAppId() {
    return appId;
  }

  public X509Certificate getAttestedCertificate() {
    return attestedCertificate;
  }

  public byte[] getClientHash() {
    return clientHash;
  }

  public String getToken() {
    return token;
  }

  public IOSReceiptType getReceiptType() {
    return receiptType;
  }

  public Instant getCreationTime() {
    return creationTime;
  }

  public Optional<Integer> getRiskMetric() {
    return Optional.ofNullable(riskMetric);
  }

  public Optional<Instant> getNotBefore() {
    return Optional.ofNullable(notBefore);
  }

  public Instant getExpirationTime() {
    return expirationTime;
  }

  /**
   * Parse the ASN.1 structure that makes up the payload.
   *
   * @param receiptAttributes list with receipt attribute sequences, parsed from signed data
   * @return parsed receipt payload.
   */
  public static IOSReceipt parseToIOSReceipt(final List<ASN1Sequence> receiptAttributes) {
    final Map<IOSReceiptAttribute, byte[]> receiptAttributeMap = readToMap(receiptAttributes);
    return new IOSReceipt(receiptAttributeMap);
  }

  private static Map<IOSReceiptAttribute, byte[]> readToMap(
      final List<ASN1Sequence> receiptAttributes) {
    final Map<IOSReceiptAttribute, byte[]> map = new EnumMap<>(IOSReceiptAttribute.class);
    receiptAttributes.forEach(
        sq -> {
          int tagNumber = ((ASN1Integer) sq.getObjectAt(0)).intValueExact();
          byte[] octets = ((DEROctetString) sq.getObjectAt(2)).getOctets();
          IOSReceiptAttribute.defineByTagNumber(tagNumber).ifPresent(k -> map.put(k, octets));
        });
    return map;
  }

  public enum IOSReceiptType {
    ATTEST,
    RECEIPT
  }
}
