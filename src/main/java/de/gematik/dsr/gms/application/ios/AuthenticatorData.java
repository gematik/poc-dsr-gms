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

package de.gematik.dsr.gms.application.ios;

import static de.gematik.dsr.gms.application.ios.AuthenticatorData.AuthenticatorDataParsingExceptionReason.UNKNOWN_FLAGS_VALUE;
import static de.gematik.dsr.gms.application.ios.AuthenticatorData.AuthenticatorDataTag.*;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Predicate;

/**
 * Parsed authenticator data. Inspired by: <a
 * href="https://medium.com/@herrjemand/verifying-fido2-responses-4691288c8770">WebAuthn/FIDO2:
 * Verifying assertion responses</a>
 *
 * <p>User information is stored in authData. AuthData is a rawBuffer struct:
 *
 * <ul>
 *   <li>RPIDHash — is the hash of the rpId which is basically the effective domain or host. For
 *       example: “https://example.com” effective domain is “example.com” *
 *   <li>Flags — 8bit flag that defines the state of the authenticator during the authentication.
 *       Bits 0 and 2 are User Presence and User Verification flags. Bit 6 is AT(Attested Credential
 *       Data). Must be set when attestedCredentialData is presented. Bit 7 must be set if extension
 *       data is presented. *
 *   <li>Counter — 4byte counter.
 * </ul>
 *
 * RPIDHash, Flags and Counter is mandatory for both Attestation and Assertion responses.
 * AttestedCredentialData is only for attestation.
 *
 * <ul>
 *   <li>AAGUID — authenticator attestation identifier — a unique identifier of authenticator model
 *   <li>CredID — Credential Identifier. The length is defined by credIdLen. Must be the same as
 *       id/rawId.
 *   <li>COSEPubKey — COSE encoded public key
 * </ul>
 */
public class AuthenticatorData {

  private final Map<AuthenticatorDataTag, byte[]> attestationStmtMap;
  private AuthenticatorDataFlag flags;
  private AttestedCredentialData attestedCredentialData;

  public AuthenticatorData(byte[] authData) {
    this();

    ByteBuffer byteBuffer =
        ByteBuffer.wrap(authData)
            .get(attestationStmtMap.get(RP_ID), 0, RP_ID.getLength())
            .get(attestationStmtMap.get(FLAGS), 0, FLAGS.getLength())
            .get(attestationStmtMap.get(COUNTER), 0, COUNTER.getLength());

    byte[] bytes = attestationStmtMap.get(AuthenticatorDataTag.FLAGS);

    flags =
        Arrays.stream(AuthenticatorDataFlag.values())
            .filter(f -> f.matches(bytes[0]))
            .findAny()
            .orElseThrow(
                () -> new GMServiceRuntimeException(UNKNOWN_FLAGS_VALUE, UUID.randomUUID()));

    if (AuthenticatorDataFlag.AT.equals(flags) && byteBuffer.remaining() > 0) {
      this.attestedCredentialData = parseAttestedCredentialDataFromBuffer(byteBuffer);
    }
  }

  private AuthenticatorData() {
    this.attestationStmtMap = new EnumMap<>(AuthenticatorDataTag.class);
    initializeEmptyByteArrays();
  }

  private void initializeEmptyByteArrays() {
    Arrays.stream(AuthenticatorDataTag.values())
        .forEach(tag -> attestationStmtMap.put(tag, new byte[tag.getLength()]));
  }

  public AuthenticatorDataFlag getFlags() {
    return flags;
  }

  public byte[] getRpId() {
    return attestationStmtMap.get(RP_ID);
  }

  public int getCounter() {
    return fromByteArray(attestationStmtMap.get(COUNTER));
  }

  public AttestedCredentialData getAttestedCredentialData() {
    return attestedCredentialData;
  }

  private AttestedCredentialData parseAttestedCredentialDataFromBuffer(
      final ByteBuffer byteBuffer) {
    byteBuffer
        .get(attestationStmtMap.get(AAGUID), 0, AAGUID.getLength())
        .get(attestationStmtMap.get(CREDENTIAL_ID_LENGTH), 0, CREDENTIAL_ID_LENGTH.getLength());

    int credIdLength = fromByteArray(attestationStmtMap.get(CREDENTIAL_ID_LENGTH));
    byte[] credentialId = new byte[credIdLength];
    byteBuffer.get(credentialId);
    int publicKeyLength = byteBuffer.remaining();
    byte[] cosePublicKey = new byte[publicKeyLength];
    byteBuffer.get(cosePublicKey);
    return new AttestedCredentialData(
        attestationStmtMap.get(AAGUID), credIdLength, credentialId, cosePublicKey);
  }

  private int fromByteArray(byte[] arrayWithLength) {
    return new BigInteger(arrayWithLength).intValueExact();
  }

  enum AuthenticatorDataTag {
    RP_ID(32) {
      @Override
      public String getDeviceHealthKey() {
        return "rpID";
      }
    },
    FLAGS(1),
    COUNTER(4),
    AAGUID(16),
    CREDENTIAL_ID_LENGTH(2);

    private final int length;

    AuthenticatorDataTag(int length) {
      this.length = length;
    }

    public int getLength() {
      return length;
    }

    public String getDeviceHealthKey() {
      return name().toLowerCase();
    }
  }

  public record AttestedCredentialData(
      byte[] aaguid, int credentialIdLength, byte[] credentialId, byte[] cosePublicKey) {

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      AttestedCredentialData that = (AttestedCredentialData) o;
      return credentialIdLength == that.credentialIdLength
          && Arrays.equals(aaguid, that.aaguid)
          && Arrays.equals(credentialId, that.credentialId)
          && Arrays.equals(cosePublicKey, that.cosePublicKey);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(credentialIdLength);
      result = 31 * result + Arrays.hashCode(aaguid);
      result = 31 * result + Arrays.hashCode(credentialId);
      result = 31 * result + Arrays.hashCode(cosePublicKey);
      return result;
    }

    @Override
    public String toString() {
      return "AttestedCredentialData{"
          + "aaguid="
          + Arrays.toString(aaguid)
          + ", credentialIdLength="
          + credentialIdLength
          + ", credentialId="
          + Arrays.toString(credentialId)
          + ", cosePublicKey="
          + Arrays.toString(cosePublicKey)
          + '}';
    }
  }

  public enum AuthenticatorDataFlag {
    /** User Presence - 0 Bit of Flags byte sequence */
    UP(aByte -> (aByte & 0x01) == 1),

    /** User Verification - 2 Bit of Flags byte sequence */
    UV((aByte -> (aByte & 0x04) == 4)),

    /** Attested Credential Data - 6 Bit of Flags byte sequence */
    AT(aByte -> (aByte & 0x40) == 64),

    /** Extension Data - 7 Bit of Flags byte sequence */
    ED(aByte -> (aByte & 0x80) == 128);

    private final Predicate<Byte> bytePredicate;

    AuthenticatorDataFlag(Predicate<Byte> bytePredicate) {
      this.bytePredicate = bytePredicate;
    }

    public boolean matches(byte flags) {
      return bytePredicate.test(flags);
    }
  }

  enum AuthenticatorDataParsingExceptionReason implements ServiceExceptionReason {
    UNKNOWN_FLAGS_VALUE(
        "Can't parse flags byte to one of known values: " + AuthenticatorDataFlag.values());

    private final String description;

    AuthenticatorDataParsingExceptionReason(String description) {
      this.description = description;
    }

    @Override
    public String getDescription() {
      return description;
    }

    @Override
    public Response.Status getStatus() {
      return Response.Status.BAD_REQUEST;
    }
  }
}
