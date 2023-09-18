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

package de.gematik.dsr.gms.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;

@Embeddable
public class DeviceAttestationSessionKey implements Serializable {

  @Column(name = "auth_code", nullable = false, columnDefinition = "TEXT")
  private String authorisationCode;

  @Column(name = "code_challenge", nullable = false, columnDefinition = "TEXT")
  private String codeChallenge;

  protected DeviceAttestationSessionKey() {
    super();
  }

  public DeviceAttestationSessionKey(final String authorisationCode, final String codeChallenge) {
    this.authorisationCode = authorisationCode;
    this.codeChallenge = codeChallenge;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    DeviceAttestationSessionKey that = (DeviceAttestationSessionKey) o;
    return Objects.equals(authorisationCode, that.authorisationCode)
        && Objects.equals(codeChallenge, that.codeChallenge);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorisationCode, codeChallenge);
  }

  @Override
  public String toString() {
    return "DeviceAttestationSessionKey{"
        + "authorisationCode='"
        + authorisationCode
        + '\''
        + ", codeChallenge='"
        + codeChallenge
        + '\''
        + '}';
  }

  public String getAuthorisationCode() {
    return authorisationCode;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }
}
