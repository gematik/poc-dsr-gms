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

import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;

public enum AttestationKeyExceptionReason implements ServiceExceptionReason {
  UNKNOWN_SECURITY_LEVEL("Can't parse value '%d' to SecurityLevel for the given version '%d'."),
  UNKNOWN_BOOT_STATE("Can't parse value '%d' to VerifiedBootState for the given RootOfTrust."),

  UNKNOWN_AUTHORIZATION_LIST_TAG(
      "Unknown authorization list tag. Can't parse tag of '%s' for the given version:'%d'."),

  INVALID_ATTESTATION_SECURITY_LEVEL(
      "Attestation security level doesn't appreciate expected values: "
          + AttestationKeyDescription.SecurityLevel.appreciatedSecurityLevels()),

  INVALID_ROOT_OF_TRUST_SEQUENCE(
      "Invalid RootOfTrust sequence, can't parse to corresponding type."),

  INVALID_ATTESTATION_APPLICATION_ID(
      "Invalid AttestationApplicationId sequence, can't parse to corresponding type.");

  private final String description;

  AttestationKeyExceptionReason(String description) {
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
