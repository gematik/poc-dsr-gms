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

import java.util.Arrays;

/**
 * Parsed from CBOR-Format 'assertion'
 *
 * @param signature Signature to validate the attested and saved public key
 * @param authenticatorData bytes containing {@link
 *     de.gematik.dsr.gms.application.ios.AuthenticatorData}, but without {@link
 *     de.gematik.dsr.gms.application.ios.AuthenticatorData.AttestedCredentialData}
 *     <p><a
 *     href="https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server#3576644">
 *     Verify the Assertion chapter </a>
 */
public record IOSAssertion(byte[] signature, byte[] authenticatorData) {
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IOSAssertion that = (IOSAssertion) o;
    return Arrays.equals(signature, that.signature)
        && Arrays.equals(authenticatorData, that.authenticatorData);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(signature);
    result = 31 * result + Arrays.hashCode(authenticatorData);
    return result;
  }

  @Override
  public String toString() {
    return "IOSAssertion{"
        + "signature="
        + Arrays.toString(signature)
        + ", authenticatorData="
        + Arrays.toString(authenticatorData)
        + '}';
  }
}
