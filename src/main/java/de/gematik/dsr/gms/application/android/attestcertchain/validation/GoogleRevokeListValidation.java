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

package de.gematik.dsr.gms.application.android.attestcertchain.validation;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

/** Validation for certificate chain to check for the Google Revoke list entries. */
public class GoogleRevokeListValidation
    implements Validation<List<X509Certificate>, List<X509Certificate>> {

  private static final int SERIAL_NUMBER_TO_STRING_RDX = 16;

  private final GoogleRevokeListRestClient revokeListRestClient;

  public GoogleRevokeListValidation(GoogleRevokeListRestClient revokeListRestClient) {
    this.revokeListRestClient = revokeListRestClient;
  }

  /**
   * Gets the current revoke list from the Google and checks, if any of certificates inside the
   * chain has match there
   *
   * @param dataToValidate certificate chain to be verified.
   * @return the same as the input, if no matches found
   * @throws GMServiceRuntimeException occurs if the chain has any match with the revoke list
   *     entries
   */
  @Override
  public List<X509Certificate> evaluate(List<X509Certificate> dataToValidate) {
    RevokeList revokeList = revokeListRestClient.getRevokeList();
    Map<String, RevokeListEntry> entries = revokeList.entries();
    long count =
        dataToValidate.stream()
            .map(X509Certificate::getSerialNumber)
            .map(sn -> sn.toString(SERIAL_NUMBER_TO_STRING_RDX))
            .map(String::toLowerCase)
            .map(entries::containsKey)
            .filter(r -> r)
            .count();

    if (count > 0) {
      throw new GMServiceRuntimeException(
          ValidationExceptionReason.REVOKE_LIST_ENTRY, UUID.randomUUID());
    }
    return dataToValidate;
  }

  @Path("/status")
  @RegisterRestClient(configKey = "google-revoke-list")
  interface GoogleRevokeListRestClient {
    @GET
    RevokeList getRevokeList();
  }

  record RevokeList(Map<String, RevokeListEntry> entries) {}

  record RevokeListEntry(
      String status,
      Optional<LocalDate> expires,
      Optional<String> reason,
      Optional<String> comment) {}
}
