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

import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyExceptionReason.INVALID_ROOT_OF_TRUST_SEQUENCE;
import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyExceptionReason.UNKNOWN_BOOT_STATE;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.asn1.*;

class RootOfTrust {

  private final byte[] verifiedBootKey;
  private final boolean deviceLocked;
  private final VerifiedBootState verifiedBootState;
  private final byte[] verifiedBootHash;

  RootOfTrust(ASN1Sequence rootOfTrustSequence, int version) {
    this.verifiedBootKey = parseFromSequence(rootOfTrustSequence, 0);

    this.deviceLocked =
        Optional.ofNullable(rootOfTrustSequence.getObjectAt(1))
            .map(ASN1Boolean.class::cast)
            .map(ASN1Boolean::isTrue)
            .orElseThrow(
                () ->
                    new GMServiceRuntimeException(
                        INVALID_ROOT_OF_TRUST_SEQUENCE, UUID.randomUUID()));

    this.verifiedBootState =
        Optional.ofNullable(rootOfTrustSequence.getObjectAt(2))
            .map(ASN1Enumerated.class::cast)
            .map(ASN1Enumerated::intValueExact)
            .map(VerifiedBootState::defineByValue)
            .orElseThrow(
                () ->
                    new GMServiceRuntimeException(
                        INVALID_ROOT_OF_TRUST_SEQUENCE, UUID.randomUUID()));

    if (version < 3) {
      this.verifiedBootHash = null;
    } else {
      this.verifiedBootHash = parseFromSequence(rootOfTrustSequence, 3);
    }
  }

  public byte[] getVerifiedBootKey() {
    return verifiedBootKey;
  }

  public boolean isDeviceLocked() {
    return deviceLocked;
  }

  public VerifiedBootState getVerifiedBootState() {
    return verifiedBootState;
  }

  public byte[] getVerifiedBootHash() {
    return verifiedBootHash;
  }

  private byte[] parseFromSequence(ASN1Sequence rootOfTrustSequence, int index) {
    return Optional.ofNullable(rootOfTrustSequence.getObjectAt(index))
        .map(ASN1OctetString.class::cast)
        .map(ASN1OctetString::getOctets)
        .orElseThrow(
            () -> new GMServiceRuntimeException(INVALID_ROOT_OF_TRUST_SEQUENCE, UUID.randomUUID()));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    RootOfTrust that = (RootOfTrust) o;
    return deviceLocked == that.deviceLocked
        && Arrays.equals(verifiedBootKey, that.verifiedBootKey)
        && verifiedBootState == that.verifiedBootState
        && Arrays.equals(verifiedBootHash, that.verifiedBootHash);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(deviceLocked, verifiedBootState);
    result = 31 * result + Arrays.hashCode(verifiedBootKey);
    result = 31 * result + Arrays.hashCode(verifiedBootHash);
    return result;
  }

  enum VerifiedBootState {
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);
    private final int value;

    VerifiedBootState(int value) {
      this.value = value;
    }

    public int getValue() {
      return value;
    }

    static VerifiedBootState defineByValue(int value) {
      return Arrays.stream(values())
          .filter(vbs -> vbs.getValue() == value)
          .findAny()
          .orElseThrow(
              () ->
                  new GMServiceRuntimeException(
                      UNKNOWN_BOOT_STATE,
                      UUID.randomUUID(),
                      String.format(UNKNOWN_BOOT_STATE.getDescription(), value)));
    }
  }
}
