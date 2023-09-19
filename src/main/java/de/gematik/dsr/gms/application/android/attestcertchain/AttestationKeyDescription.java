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

import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyDescription.AttestationKeyDescriptionTags.*;
import static de.gematik.dsr.gms.application.android.attestcertchain.AttestationKeyExceptionReason.UNKNOWN_SECURITY_LEVEL;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;
import org.bouncycastle.asn1.*;

public class AttestationKeyDescription {

  private static final ToIntFunction<ASN1Encodable> PARSE_TO_INTEGER =
      encodable -> ((ASN1Integer) encodable).intValueExact();

  private static final Function<ASN1Encodable, byte[]> PARSE_TO_OCTET_STRING_VALUE =
      encodable -> ((ASN1OctetString) encodable).getOctets();

  private static final BiFunction<ASN1Encodable, Integer, SecurityLevel> PARSE_TO_SECURITY_LEVEL =
      (encodable, version) ->
          SecurityLevel.defineByValue(((ASN1Enumerated) encodable).getValue().intValue(), version);

  private final int attestationVersion;
  private final SecurityLevel attestationSecurityLevel;
  private final int keymasterVersion;
  private final SecurityLevel keymasterSecurityLevel;
  /** Generated nonce value */
  private final byte[] attestationChallenge;

  private final byte[] uniqueId;
  private final AuthorizationList softwareEnforced;
  private final AuthorizationList teeEnforced;

  private AttestationKeyDescription(ASN1Sequence keyDescriptionSequence) {
    this.attestationVersion =
        PARSE_TO_INTEGER.applyAsInt(
            keyDescriptionSequence.getObjectAt(ATTESTATION_VERSION.getIndex()));
    this.attestationChallenge =
        PARSE_TO_OCTET_STRING_VALUE.apply(
            keyDescriptionSequence.getObjectAt(ATTESTATION_CHALLENGE.getIndex()));
    this.attestationSecurityLevel =
        PARSE_TO_SECURITY_LEVEL.apply(
            keyDescriptionSequence.getObjectAt(ATTESTATION_SECURITY_LEVEL.getIndex()),
            attestationVersion);
    this.keymasterVersion =
        PARSE_TO_INTEGER.applyAsInt(
            keyDescriptionSequence.getObjectAt(KEY_MASTER_OR_KEY_MINT_VERSION.getIndex()));
    this.keymasterSecurityLevel =
        PARSE_TO_SECURITY_LEVEL.apply(
            keyDescriptionSequence.getObjectAt(KEY_MASTER_OR_KEY_MINT_SECURITY_LEVEL.getIndex()),
            keymasterVersion);
    this.uniqueId =
        PARSE_TO_OCTET_STRING_VALUE.apply(keyDescriptionSequence.getObjectAt(UNIQUE_ID.getIndex()));
    this.softwareEnforced =
        new AuthorizationList(
            (ASN1Sequence) keyDescriptionSequence.getObjectAt(SOFTWARE_ENFORCED.getIndex()),
            attestationVersion);
    this.teeEnforced =
        new AuthorizationList(
            (ASN1Sequence) keyDescriptionSequence.getObjectAt(TEE_ENFORCED.getIndex()),
            attestationVersion);
  }

  public int getAttestationVersion() {
    return attestationVersion;
  }

  public SecurityLevel getAttestationSecurityLevel() {
    return attestationSecurityLevel;
  }

  public KeyStore getKeyStore() {
    KeyStoreType type = KeyStoreType.getForApplicationVersion(getAttestationVersion());
    return new KeyStore(type, getKeymasterVersion(), getKeymasterSecurityLevel());
  }

  @JsonIgnore
  public int getKeymasterVersion() {
    return keymasterVersion;
  }

  @JsonIgnore
  public SecurityLevel getKeymasterSecurityLevel() {
    return keymasterSecurityLevel;
  }

  @JsonIgnore
  public byte[] getAttestationChallenge() {
    return attestationChallenge;
  }

  @JsonIgnore
  public byte[] getUniqueId() {
    return uniqueId;
  }

  public AuthorizationList getSoftwareEnforced() {
    return softwareEnforced;
  }

  public AuthorizationList getTeeEnforced() {
    return teeEnforced;
  }

  enum AttestationKeyDescriptionTags {
    ATTESTATION_VERSION(0),
    ATTESTATION_SECURITY_LEVEL(1),
    KEY_MASTER_OR_KEY_MINT_VERSION(2),
    KEY_MASTER_OR_KEY_MINT_SECURITY_LEVEL(3),
    ATTESTATION_CHALLENGE(4),
    UNIQUE_ID(5),
    SOFTWARE_ENFORCED(6),
    TEE_ENFORCED(7);
    private final int index;

    AttestationKeyDescriptionTags(int index) {
      this.index = index;
    }

    public int getIndex() {
      return index;
    }
  }

  public enum SecurityLevel implements Predicate<Integer> {
    SOFTWARE(0),
    TRUSTED_ENVIRONMENT(1),
    STRONG_BOX(2) {
      @Override
      public boolean test(Integer version) {
        return version >= 3;
      }
    };
    private final int value;

    SecurityLevel(int value) {
      this.value = value;
    }

    static SecurityLevel defineByValue(int value, int version) {
      return Arrays.stream(values())
          .filter(sl -> sl.test(version))
          .filter(sl -> sl.value == value)
          .findAny()
          .orElseThrow(
              () ->
                  new GMServiceRuntimeException(
                      UNKNOWN_SECURITY_LEVEL,
                      UUID.randomUUID(),
                      String.format(UNKNOWN_SECURITY_LEVEL.getDescription(), value, version)));
    }

    public static Set<SecurityLevel> appreciatedSecurityLevels() {
      return Set.of(TRUSTED_ENVIRONMENT, STRONG_BOX);
    }

    @Override
    public boolean test(Integer version) {
      return true;
    }

    @JsonValue
    public int getValue() {
      return value;
    }
  }

  public static AttestationKeyDescription createAttestationKeyDescription(
      ASN1Sequence keyDescriptionSequence) {
    return new AttestationKeyDescription(keyDescriptionSequence);
  }

  enum KeyStoreType {
    KEY_MASTER,

    KEY_MINT;

    static KeyStoreType getForApplicationVersion(int version) {
      if (version == 100 || version == 200) {
        return KEY_MINT;
      }
      return KEY_MASTER;
    }
  }

  record KeyStore(KeyStoreType type, int version, SecurityLevel securityLevel) {}
}
