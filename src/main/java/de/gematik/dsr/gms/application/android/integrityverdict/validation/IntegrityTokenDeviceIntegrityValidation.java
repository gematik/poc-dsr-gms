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

import static de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict.DeviceIntegrityVerdict.MEETS_DEVICE_INTEGRITY;
import static de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityTokenDeviceIntegrityValidation.DeviceIntegrityValidationReason.*;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;
import java.util.UUID;
import org.jboss.logging.Logger;

public class IntegrityTokenDeviceIntegrityValidation
    implements Validation<IntegrityVerdict.TokenPayloadExternal, IntegrityVerdict.DeviceIntegrity> {

  private static final Logger LOG = Logger.getLogger(IntegrityTokenDeviceIntegrityValidation.class);

  private final boolean validateVerdict;

  public IntegrityTokenDeviceIntegrityValidation(boolean validateVerdict) {
    this.validateVerdict = validateVerdict;
  }

  @Override
  public IntegrityVerdict.DeviceIntegrity evaluate(
      IntegrityVerdict.TokenPayloadExternal dataToValidate) {
    IntegrityVerdict.DeviceIntegrity deviceIntegrity = verifyDeviceIntegrity(dataToValidate);
    checkDeviceIntegrity(deviceIntegrity);
    return deviceIntegrity;
  }

  private IntegrityVerdict.DeviceIntegrity verifyDeviceIntegrity(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal) {
    IntegrityVerdict.DeviceIntegrity deviceIntegrity = tokenPayloadExternal.deviceIntegrity();
    if (deviceIntegrity == null || deviceIntegrity.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Error getting device integrity from external google token payload.", traceId);
      throw new GMServiceRuntimeException(MISSING_DEVICE_INTEGRITY, UUID.randomUUID());
    }
    return deviceIntegrity;
  }

  private void checkDeviceIntegrity(IntegrityVerdict.DeviceIntegrity deviceIntegrity) {
    if (!validateVerdict) {
      LOG.infof("Verdicts %s are not validated!", deviceIntegrity.getVerdicts());
      return;
    }
    try {
      if (deviceIntegrity.getVerdicts().stream().noneMatch(MEETS_DEVICE_INTEGRITY::equals)) {
        throw new GMServiceRuntimeException(DEVICE_INTEGRITY_VIOLATIONS, UUID.randomUUID());
      }

    } catch (IllegalArgumentException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Error parsing device integrity verdict from external google token payload. Cant parse"
              + " to known values: %s",
          traceId, IntegrityVerdict.DeviceIntegrityVerdict.values());
      throw new GMServiceRuntimeException(UNKNOWN_DEVICE_INTEGRITY_VERDICT, traceId, e);
    }
  }

  enum DeviceIntegrityValidationReason implements ServiceExceptionReason {
    DEVICE_INTEGRITY_VIOLATIONS("Device integrity is violated due to its status"),

    MISSING_DEVICE_INTEGRITY("No device integrity value"),
    UNKNOWN_DEVICE_INTEGRITY_VERDICT(
        "Not parsable or unknown device integrity value. Possible values are: "
            + IntegrityVerdict.DeviceIntegrityVerdict.values());

    private final String description;

    DeviceIntegrityValidationReason(String description) {
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
