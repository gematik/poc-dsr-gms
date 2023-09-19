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

import de.gematik.dsr.gms.application.ios.AuthenticatorData;
import java.util.Arrays;
import java.util.Objects;

/**
 * The Result of assertion verification step. Contains data needed for the further verification
 * process.
 *
 * @param authenticatorData parsed {@link IOSAssertion#authenticatorData()} bytes
 * @param attestedDeviceKey calculated fingerprint of the attested public key, which was saved while
 *     registration.
 * @see de.gematik.dsr.gms.application.ios.AuthenticatorData
 */
public record IOSAssertionResult(AuthenticatorData authenticatorData, byte[] attestedDeviceKey) {
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IOSAssertionResult that = (IOSAssertionResult) o;
    return Objects.equals(authenticatorData, that.authenticatorData)
        && Arrays.equals(attestedDeviceKey, that.attestedDeviceKey);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(authenticatorData);
    result = 31 * result + Arrays.hashCode(attestedDeviceKey);
    return result;
  }

  @Override
  public String toString() {
    return "IOSAssertionResult{"
        + "authenticatorData="
        + authenticatorData
        + ", attestedDeviceKey="
        + Arrays.toString(attestedDeviceKey)
        + '}';
  }
}
