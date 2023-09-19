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

import static de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityTokenRequestDetailsValidation.RequestDetailsValidationReason.*;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.exception.ServiceExceptionReason;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import org.jboss.logging.Logger;

public class IntegrityTokenRequestDetailsValidation
    implements Validation<IntegrityVerdict.TokenPayloadExternal, IntegrityVerdict.RequestDetails> {
  private static final Logger LOG = Logger.getLogger(IntegrityTokenRequestDetailsValidation.class);
  private final Duration millisDuration;
  private final String packageName;
  private final Consumer<IntegrityVerdict.RequestDetails> nonceVerification;

  private final Clock clock;

  public IntegrityTokenRequestDetailsValidation(
      Duration millisDuration,
      String packageName,
      Consumer<IntegrityVerdict.RequestDetails> nonceVerification,
      Clock clock) {
    this.millisDuration = millisDuration;
    this.packageName = packageName;
    this.nonceVerification = nonceVerification;
    this.clock = clock;
  }

  @Override
  public IntegrityVerdict.RequestDetails evaluate(
      IntegrityVerdict.TokenPayloadExternal dataToValidate) {
    IntegrityVerdict.RequestDetails requestDetails = verifyRequestDetails(dataToValidate);
    checkRequestDetails(requestDetails);
    return requestDetails;
  }

  private IntegrityVerdict.RequestDetails verifyRequestDetails(
      IntegrityVerdict.TokenPayloadExternal tokenPayloadExternal) {
    IntegrityVerdict.RequestDetails requestDetails = tokenPayloadExternal.requestDetails();
    if (requestDetails == null || requestDetails.isEmpty()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Error getting device integrity from external google token payload.", traceId);
      throw new GMServiceRuntimeException(MISSING_REQUEST_DETAILS, UUID.randomUUID());
    }
    return requestDetails;
  }

  private void checkRequestDetails(IntegrityVerdict.RequestDetails requestDetails) {
    nonceVerification.accept(requestDetails);

    long timestampMillis = requestDetails.timestampMillis();
    long currentTimestampMillis = Instant.now(clock).toEpochMilli();
    if (currentTimestampMillis - timestampMillis > millisDuration.toMillis()) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Integrity verdict is already expired.", traceId);
      throw new GMServiceRuntimeException(REQUEST_DETAILS_EXPIRED_VIOLATION, traceId);
    }

    String requestPackageName = requestDetails.requestPackageName();
    if (!packageName.equals(requestPackageName)) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Requested verdict package name mismatch.", traceId);
      throw new GMServiceRuntimeException(REQUEST_DETAILS_PACKAGE_VIOLATION, traceId);
    }
  }

  enum RequestDetailsValidationReason implements ServiceExceptionReason {
    REQUEST_DETAILS_PACKAGE_VIOLATION(
        "Integrity verdict is violated due to  requested package name mismatch."),

    MISSING_REQUEST_DETAILS("No request details are available"),

    REQUEST_DETAILS_EXPIRED_VIOLATION("Integrity verdict is already expired");

    private final String description;

    RequestDetailsValidationReason(String description) {
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
