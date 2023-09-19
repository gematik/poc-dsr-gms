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

import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;

public enum IOSValidationReason implements ServiceExceptionReason {
  INVALID_CBOR_FORMAT("Invalid attestation data, can't parse CBOR format."),

  INVALID_FORMAT_IDENTIFIER("Invalid format identification data, unexpected value"),

  NOT_PARSABLE_NONCE_SEQUENCE("Can't parse sequence to extract nonce."),

  INVALID_RP_ID("RP ID doesn't match to any known application ID"),

  INVALID_KEY_ID("Key identifier doesn't match to public key hash"),

  INVALID_COUNTER("Counter value doesn't match expected value"),

  INVALID_SIGNATURE_FOR_NONCE("Assertion signature is invalid for nonce"),

  UNSUITABLE_KEY_FOR_SIGNATURE("Failed to initialize signature with the registered public key"),

  UNEXPECTED_ATTESTATION_FLAGS(
      "Expected authenticated data flags while attestation is "
          + AuthenticatorData.AuthenticatorDataFlag.AT
          + ": Attested Credential Data"),
  DEVICE_RECEIPT_NOT_FOUND("Device receipt not found"),
  UNEXPECTED_AAGUID_FIELD("Expected aagiud field values are either appattestdevelop or appattest"),

  UNREADABLE_RECEIPT("The receipt is not parsable to signed content instance of pkcs7 container"),

  INVALID_PKCS7_SIGNATURE("The receipt signed content has unverified signature"),

  INVALID_PKCS7_CERTIFICATES("The receipt signed content has unreadable certificates"),
  UNEXPECTED_RECEIPT_APP_ID("Unexpected receipt application ID"),
  UNEXPECTED_RECEIPT_ATTESTED_KEY(
      "Public key from receipt and attestation statement doesn't match."),
  TOO_LONG_AGO_CREATED_RECEIPT("Receipt creation time is exceeds the max allowed age."),
  MISSING_RECEIPT_ATTRIBUTE("Missing receipt attribute."),

  INVALID_APPLE_RECEIPT_EXCHANGE(
      "Response status code from apple while receipt exchanging is not ok.");

  private final String description;

  IOSValidationReason(String description) {
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
