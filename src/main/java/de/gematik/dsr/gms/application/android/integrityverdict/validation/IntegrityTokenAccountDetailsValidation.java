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

package de.gematik.dsr.gms.application.android.integrityverdict.validation;

import static de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict.AppLicenseVerdict.LICENSED;
import static de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityTokenAccountDetailsValidation.AccountDetailsValidationReason.*;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;
import java.util.UUID;
import org.jboss.logging.Logger;

public class IntegrityTokenAccountDetailsValidation
    implements Validation<IntegrityVerdict.TokenPayloadExternal, IntegrityVerdict.AccountDetails> {

  private static final Logger LOG = Logger.getLogger(IntegrityTokenAccountDetailsValidation.class);

  private final boolean validateVerdict;

  public IntegrityTokenAccountDetailsValidation(boolean validateVerdict) {
    this.validateVerdict = validateVerdict;
  }

  @Override
  public IntegrityVerdict.AccountDetails evaluate(
      IntegrityVerdict.TokenPayloadExternal dataToValidate) {
    IntegrityVerdict.AccountDetails accountDetails = verifyAccountDetails(dataToValidate);
    checkAccountDetails(accountDetails);
    return accountDetails;
  }

  private IntegrityVerdict.AccountDetails verifyAccountDetails(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal) {
    IntegrityVerdict.AccountDetails accountDetails = tokenPayloadExternal.accountDetails();
    if (accountDetails == null || accountDetails.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Error getting account details from external google token payload.", traceId);
      throw new GMServiceRuntimeException(MISSING_ACCOUNT_DETAILS, UUID.randomUUID());
    }
    return accountDetails;
  }

  private void checkAccountDetails(IntegrityVerdict.AccountDetails accountDetails) {
    if (!validateVerdict) {
      LOG.infof("Verdict %s is not validated!", accountDetails.getVerdict());
      return;
    }
    try {
      IntegrityVerdict.AppLicenseVerdict appLicenseVerdict = accountDetails.getVerdict();
      if (!LICENSED.equals(appLicenseVerdict)) {
        throw new GMServiceRuntimeException(ACCOUNT_DETAILS_VIOLATIONS, UUID.randomUUID());
      }
    } catch (IllegalArgumentException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Error parsing app licensing verdict from external google token payload. Cannot parse"
              + " to known values: %s",
          traceId, IntegrityVerdict.AppLicenseVerdict.values());
      throw new GMServiceRuntimeException(UNKNOWN_ACCOUNT_DETAILS_LICENSE_VERDICT, traceId, e);
    }
  }

  enum AccountDetailsValidationReason implements ServiceExceptionReason {
    ACCOUNT_DETAILS_VIOLATIONS("Account details are violated due to its license value"),

    MISSING_ACCOUNT_DETAILS("No account details value"),
    UNKNOWN_ACCOUNT_DETAILS_LICENSE_VERDICT(
        "Not parsable or unknown license verdict value. Possible values are: "
            + IntegrityVerdict.AppLicenseVerdict.values());

    private final String description;

    AccountDetailsValidationReason(String description) {
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
