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

package de.gematik.dsr.gms.application.android.attestcertchain;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.bouncycastle.asn1.*;

class AttestationApplicationId {

  private final List<AttestationPackageInfo> packageInfos;
  private final List<byte[]> signatureDigests;

  AttestationApplicationId(byte[] octets) {
    try {
      ASN1Sequence asn1Sequence = (ASN1Sequence) ASN1Primitive.fromByteArray(octets);
      this.packageInfos = parseToPackageInfos(parseToSet(asn1Sequence, 0));
      this.signatureDigests = parseToSignatureDigests(parseToSet(asn1Sequence, 1));
    } catch (IOException e) {
      throw new GMServiceRuntimeException(
          AttestationKeyExceptionReason.INVALID_ATTESTATION_APPLICATION_ID, UUID.randomUUID());
    }
  }

  private ASN1Set parseToSet(ASN1Sequence asn1Sequence, int position) {
    return Optional.ofNullable(asn1Sequence.getObjectAt(position))
        .map(ASN1Set.class::cast)
        .orElseThrow(
            () ->
                new GMServiceRuntimeException(
                    AttestationKeyExceptionReason.INVALID_ATTESTATION_APPLICATION_ID,
                    UUID.randomUUID()));
  }

  private List<AttestationPackageInfo> parseToPackageInfos(ASN1Set asn1Encodables) {
    final List<AttestationPackageInfo> result = new ArrayList<>(asn1Encodables.size());
    for (ASN1Encodable encodable : asn1Encodables) {
      ASN1Sequence sequence = (ASN1Sequence) encodable;
      final String packageName =
          Optional.ofNullable(sequence.getObjectAt(0))
              .map(ASN1OctetString.class::cast)
              .map(ASN1OctetString::getOctets)
              .map(oc -> new String(oc, StandardCharsets.UTF_8))
              .orElseThrow(
                  () ->
                      new GMServiceRuntimeException(
                          AttestationKeyExceptionReason.INVALID_ATTESTATION_APPLICATION_ID,
                          UUID.randomUUID()));

      long version =
          Optional.ofNullable(sequence.getObjectAt(1))
              .map(ASN1Integer.class::cast)
              .map(ASN1Integer::getValue)
              .map(BigInteger::longValue)
              .orElseThrow(
                  () ->
                      new GMServiceRuntimeException(
                          AttestationKeyExceptionReason.INVALID_ATTESTATION_APPLICATION_ID,
                          UUID.randomUUID()));
      result.add(new AttestationPackageInfo(packageName, version));
    }
    return result;
  }

  private List<byte[]> parseToSignatureDigests(ASN1Set asn1Encodables) {
    final List<byte[]> digests = new ArrayList<>(asn1Encodables.size());
    for (ASN1Encodable encodable : asn1Encodables) {
      digests.add(((ASN1OctetString) encodable).getOctets());
    }
    return digests;
  }

  public List<AttestationPackageInfo> getPackageInfos() {
    return packageInfos;
  }

  public List<byte[]> getSignatureDigests() {
    return signatureDigests;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AttestationApplicationId that = (AttestationApplicationId) o;
    return Objects.equals(packageInfos, that.packageInfos)
        && Objects.equals(signatureDigests, that.signatureDigests);
  }

  @Override
  public int hashCode() {
    return Objects.hash(packageInfos, signatureDigests);
  }

  record AttestationPackageInfo(String packageName, long version) {}
}
