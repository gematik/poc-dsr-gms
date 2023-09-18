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

package de.gematik.dsr.gms.application.exception;

import static jakarta.ws.rs.core.Response.Status;

public enum GMServiceExceptionReason implements ServiceExceptionReason {
  INTERNAL_SERVER_ERROR("Common internal Server Error", Status.INTERNAL_SERVER_ERROR),
  DEVICE_REGISTRATION_NOT_FOUND("Device registration not found", Status.BAD_REQUEST),
  DEVICE_ATTESTATION_SESSION_NOT_FOUND(
      "No device attestation session found by the given auth code and PKCE code verifier",
      Status.BAD_REQUEST),
  INVALID_TOKEN("Token is invalid", Status.BAD_REQUEST),
  INVALID_TOKEN_SYNTAX("Missing required claims at token", Status.BAD_REQUEST),
  INVALID_TOKEN_ISSUER("Invalid issuer or invalid issuer format", Status.BAD_REQUEST),
  UNSUPPORTED_ISSUER_VERSION("Unsupported issuer version", Status.BAD_REQUEST),
  NONCE_INVALID("Invalid or unknown nonce", Status.BAD_REQUEST),
  NONCE_EXPIRED("Nonce already expired", Status.BAD_REQUEST),
  CSR_INVALID("Invalid CSR", Status.BAD_REQUEST),
  CSR_ERROR("Error on parsing of the CSR", Status.INTERNAL_SERVER_ERROR),
  MISSING_USER_IDENTITY("Missing suitable attribute at certificate", Status.BAD_REQUEST),
  CERTIFICATE_ENCODING_PROBLEM("Unable to encode certificate", Status.INTERNAL_SERVER_ERROR),
  FAIL_ON_RESOURCE_READING("Impossible to read classpath resource", Status.INTERNAL_SERVER_ERROR),
  DEVICE_ALREADY_REGISTERED("Device already registered for the given user", Status.BAD_REQUEST),
  ALGORITHM_INITIALISATION_ERROR("Unknown algorithm", Status.INTERNAL_SERVER_ERROR),
  TOKEN_EXPIRED("Token already expired", Status.BAD_REQUEST),
  INVALID_CLIENT_CERTIFICATE("The client certificate is invalid", Status.BAD_REQUEST),
  UNSUITABLE_CLIENT_CERTIFICATE(
      "Unsuitable client certificate in relation to the token", Status.BAD_REQUEST),
  UNKNOWN_DEVICE_TYPE(
      "Unknown device type, impossible to find suitable device attestation", Status.BAD_REQUEST),
  FAILED_TO_LOAD_GOOGLE_CREDENTIALS(
      "Error while reading credentials template", Status.INTERNAL_SERVER_ERROR);

  private final String description;
  private final Status status;

  GMServiceExceptionReason(final String description, final Status status) {
    this.description = description;
    this.status = status;
  }

  @Override
  public String getDescription() {
    return description;
  }

  public Status getStatus() {
    return status;
  }
}
