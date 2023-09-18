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

import java.util.Arrays;
import java.util.Objects;

public record AttestationResult(
    byte[] deviceKeyFingerprint, AttestationKeyDescription attestationKeyDescription) {
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AttestationResult that = (AttestationResult) o;
    return Arrays.equals(deviceKeyFingerprint, that.deviceKeyFingerprint)
        && Objects.equals(attestationKeyDescription, that.attestationKeyDescription);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(attestationKeyDescription);
    result = 31 * result + Arrays.hashCode(deviceKeyFingerprint);
    return result;
  }

  @Override
  public String toString() {
    return "AttestationResult{"
        + "deviceKeyFingerprint="
        + Arrays.toString(deviceKeyFingerprint)
        + ", attestationKeyDescription="
        + attestationKeyDescription
        + '}';
  }
}
