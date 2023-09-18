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

package de.gematik.dsr.gms.web;

import static jakarta.ws.rs.core.Response.*;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.web.model.WebServiceErrorDTO;
import de.gematik.idp.exceptions.IdpJwtSignatureInvalidException;
import io.quarkus.runtime.util.StringUtil;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.UUID;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

class ExceptionMappers {

  @Context UriInfo uriInfo;

  private static final Logger LOG = Logger.getLogger(ExceptionMappers.class);

  @ServerExceptionMapper
  public RestResponse<WebServiceErrorDTO> mapException(GMServiceRuntimeException exception) {

    LOG.infof(
        exception.getCause(),
        "%s Handling GMServiceRuntimeException on request path: %s",
        exception.getTraceId(),
        uriInfo.getAbsolutePath());

    WebServiceErrorDTO entity;
    if (!StringUtil.isNullOrEmpty(exception.getMessage())) {
      entity =
          new WebServiceErrorDTO(
              exception.getReason().getErrorCode(), exception.getMessage(), exception.getTraceId());
    } else {
      entity =
          new WebServiceErrorDTO(
              exception.getReason().getErrorCode(),
              exception.getReason().getDescription(),
              exception.getTraceId());
    }

    return RestResponse.status(exception.getReason().getStatus(), entity);
  }

  @ServerExceptionMapper
  public RestResponse<WebServiceErrorDTO> mapException(ConstraintViolationException exception) {
    final UUID traceId = UUID.randomUUID();
    LOG.infof(
        "%s Handling ConstraintViolationException on request path: %s",
        traceId, uriInfo.getAbsolutePath());

    final String message =
        exception.getConstraintViolations().stream()
            .map(ConstraintViolation::getMessage)
            .collect(Collectors.joining(", "));
    final var entity = new WebServiceErrorDTO("CONSTRAINT_VIOLATION", message, traceId);
    return RestResponse.status(Status.BAD_REQUEST, entity);
  }

  @ServerExceptionMapper
  public RestResponse<WebServiceErrorDTO> mapException(IdpJwtSignatureInvalidException exception) {
    final UUID traceId = UUID.randomUUID();
    LOG.warnf(
        "%s Handling IdpJwtSignatureInvalidException on request path: %s",
        traceId, uriInfo.getAbsolutePath());
    final var entity =
        new WebServiceErrorDTO("JWT_INVALID_SIGNATURE", exception.getLocalizedMessage(), traceId);
    return RestResponse.status(Status.BAD_REQUEST, entity);
  }

  @ServerExceptionMapper
  public Response mapException(Exception exception) {

    if (exception instanceof WebApplicationException webApplicationException) {
      LOG.debugf("Handling WebApplicationException on request path: %s", uriInfo.getAbsolutePath());
      return webApplicationException.getResponse();
    }

    final UUID traceId = UUID.randomUUID();
    LOG.errorf(
        "%s Handling unhandled Exception on request path: %s", traceId, uriInfo.getAbsolutePath());
    final var exceptionMessage =
        exception.getLocalizedMessage() != null
            ? exception.getLocalizedMessage()
            : exception.getMessage();
    LOG.errorf(exception, "%s %s", traceId, exceptionMessage);

    final var entity =
        new WebServiceErrorDTO(
            Status.INTERNAL_SERVER_ERROR.name(),
            Status.INTERNAL_SERVER_ERROR.getReasonPhrase(),
            traceId);
    return Response.status(Status.INTERNAL_SERVER_ERROR).entity(entity).build();
  }
}
