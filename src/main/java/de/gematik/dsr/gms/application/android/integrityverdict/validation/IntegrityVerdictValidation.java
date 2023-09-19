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

import de.gematik.dsr.gms.application.MasterDataRepository;
import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdictGoogleClient;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import de.gematik.dsr.gms.application.util.SystemClockProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class IntegrityVerdictValidation
    implements Validation<
        IntegrityVerdict.IntegrityVerdictToken, IntegrityVerdict.TokenPayloadExternal> {
  private final IntegrityVerdictGoogleClient integrityVerdictGoogleClient;
  private final Duration expirationMinutes;
  private final MasterDataRepository masterDataRepository;
  private final Clock clock;

  public IntegrityVerdictValidation(
      final IntegrityVerdictGoogleClient integrityVerdictGoogleClient,
      @ConfigProperty(name = "android.integrity-verdict.expiration-period", defaultValue = "10")
          long minutes,
      final MasterDataRepository masterDataRepository,
      SystemClockProvider systemClockProvider) {
    this.integrityVerdictGoogleClient = integrityVerdictGoogleClient;
    this.expirationMinutes = Duration.ofMinutes(minutes);
    this.masterDataRepository = masterDataRepository;
    this.clock = systemClockProvider.systemClock();
  }

  @Override
  public IntegrityVerdict.TokenPayloadExternal evaluate(
      IntegrityVerdict.IntegrityVerdictToken dataToValidate) {
    IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal =
        integrityVerdictGoogleClient.decodeIntegrityToken(
            dataToValidate.packageName(), dataToValidate.integrityToken());
    boolean validatedVerdicts = dataToValidate.validateVerdicts();
    IntegrityVerdict.RequestDetails requestDetails =
        checkRequestDetails(dataToValidate, tokenPayloadExternal);
    IntegrityVerdict.AppIntegrity appIntegrity =
        checkAppIntegrity(dataToValidate.packageName(), tokenPayloadExternal, validatedVerdicts);
    IntegrityVerdict.DeviceIntegrity deviceIntegrity =
        checkDeviceIntegrity(tokenPayloadExternal, validatedVerdicts);
    IntegrityVerdict.AccountDetails accountDetails =
        checkAccountDetails(tokenPayloadExternal, validatedVerdicts);
    return new IntegrityVerdict.TokenPayloadExternal(
        requestDetails, appIntegrity, deviceIntegrity, accountDetails);
  }

  private IntegrityVerdict.AppIntegrity checkAppIntegrity(
      String packageName,
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal,
      boolean validateVerdict) {
    IntegrityTokenAppIntegrityValidation appIntegrityValidation =
        new IntegrityTokenAppIntegrityValidation(
            packageName, masterDataRepository.getAvailablePackages(), validateVerdict);
    return appIntegrityValidation.evaluate(tokenPayloadExternal);
  }

  private IntegrityVerdict.DeviceIntegrity checkDeviceIntegrity(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal, boolean validateVerdict) {
    IntegrityTokenDeviceIntegrityValidation deviceIntegrityValidation =
        new IntegrityTokenDeviceIntegrityValidation(validateVerdict);
    return deviceIntegrityValidation.evaluate(tokenPayloadExternal);
  }

  private IntegrityVerdict.AccountDetails checkAccountDetails(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal, boolean validateVerdict) {
    IntegrityTokenAccountDetailsValidation accountDetailsValidation =
        new IntegrityTokenAccountDetailsValidation(validateVerdict);
    return accountDetailsValidation.evaluate(tokenPayloadExternal);
  }

  private IntegrityVerdict.RequestDetails checkRequestDetails(
      IntegrityVerdict.IntegrityVerdictToken dataToValidate,
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal) {
    IntegrityTokenRequestDetailsValidation requestDetailsValidation =
        new IntegrityTokenRequestDetailsValidation(
            expirationMinutes, dataToValidate.packageName(), dataToValidate.nonceVerifier(), clock);
    return requestDetailsValidation.evaluate(tokenPayloadExternal);
  }

  enum IntegrityVerdictValidationInitializationReason implements ServiceExceptionReason {
    FAILED_TO_READ_DECODE_INTEGRITY_RESPONSE("Error while executing and reading google response");

    private final String description;

    IntegrityVerdictValidationInitializationReason(String description) {
      this.description = description;
    }

    @Override
    public String getDescription() {
      return description;
    }

    @Override
    public Response.Status getStatus() {
      return Response.Status.INTERNAL_SERVER_ERROR;
    }
  }
}
