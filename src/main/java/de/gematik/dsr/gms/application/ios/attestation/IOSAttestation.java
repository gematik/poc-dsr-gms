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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Parsed from CBOR-Format 'attestation'
 *
 * @param fmt Attestation Statement Format
 * @param attStmt Attestation Statement, containing bytes with certificate chain and receipt.
 * @param authData bytes containing {@link de.gematik.dsr.gms.application.ios.AuthenticatorData}
 *     with {@link de.gematik.dsr.gms.application.ios.AuthenticatorData.AttestedCredentialData}
 *     <p><a
 *     href="https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576643">
 *     Verify the Attestation chapter </a>
 */
public record IOSAttestation(String fmt, AttestationStatement attStmt, byte[] authData)
    implements Serializable {
  static final String FORMAT_IDENTIFIER = "apple-appattest";

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IOSAttestation that = (IOSAttestation) o;
    return Objects.equals(fmt, that.fmt)
        && Objects.equals(attStmt, that.attStmt)
        && Arrays.equals(authData, that.authData);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(fmt, attStmt);
    result = 31 * result + Arrays.hashCode(authData);
    return result;
  }

  @Override
  public String toString() {
    return "IOSAttestation{"
        + "fmt='"
        + fmt
        + '\''
        + ", attStmt="
        + attStmt
        + ", authData="
        + Arrays.toString(authData)
        + '}';
  }
}
