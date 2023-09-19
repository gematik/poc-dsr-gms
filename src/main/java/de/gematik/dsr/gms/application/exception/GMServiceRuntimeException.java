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

import java.util.UUID;

public class GMServiceRuntimeException extends RuntimeException implements ExceptionReasonProvider {

  private final ServiceExceptionReason reason;
  private final UUID traceId;

  public GMServiceRuntimeException(
      final ServiceExceptionReason reason,
      final UUID traceId,
      final String message,
      final Throwable cause) {
    super(message, cause);
    this.reason = reason;
    this.traceId = traceId;
  }

  public GMServiceRuntimeException(
      final ServiceExceptionReason reason, final UUID traceId, final Throwable cause) {
    this(reason, traceId, reason.getDescription(), cause);
  }

  public GMServiceRuntimeException(
      final ServiceExceptionReason reason, final UUID traceId, final String message) {
    this(reason, traceId, message, null);
  }

  public GMServiceRuntimeException(final ServiceExceptionReason reason, final UUID traceId) {
    this(reason, traceId, reason.getDescription(), null);
  }

  public GMServiceRuntimeException(final ServiceExceptionReason reason) {
    this(reason, UUID.randomUUID(), reason.getDescription(), null);
  }

  @Override
  public ServiceExceptionReason getReason() {
    return reason;
  }

  @Override
  public UUID getTraceId() {
    return traceId;
  }
}
