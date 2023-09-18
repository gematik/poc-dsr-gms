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

import de.gematik.dsr.gms.application.DeviceRegistrationService;
import de.gematik.dsr.gms.domain.DeviceRegistrationEntity;
import de.gematik.dsr.gms.web.model.DeviceRegistrationDTO;
import de.gematik.dsr.gms.web.model.DeviceType;
import jakarta.inject.Inject;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Comparator;

@Path("/device-registrations")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class DeviceRegistrationResource {

  @Inject DeviceRegistrationService deviceRegistrationService;

  @GET
  public Response getDeviceRegistrationsByUser(
      @QueryParam("userIdentifier")
          @NotBlank(message = "Required query parameter 'userIdentifier' missing")
          final String userIdentifier) {
    final var deviceRegistrationEntities =
        deviceRegistrationService.getDeviceRegistrationsByUser(userIdentifier);
    final var result =
        deviceRegistrationEntities.stream()
            .map(DeviceRegistrationResource::mapDeviceRegistrationEntity)
            .sorted(Comparator.comparing(DeviceRegistrationDTO::createdAt))
            .toList();
    return Response.ok(result).build();
  }

  @DELETE
  public Response deleteDeviceRegistrations(
      @QueryParam("userIdentifier")
          @NotBlank(message = "Required query parameter 'userIdentifier' missing")
          final String userIdentifier,
      @QueryParam("deviceIdentifier")
          @NotBlank(message = "Required query parameter 'deviceIdentifier' missing")
          final String deviceIdentifier) {

    deviceRegistrationService.deleteDeviceRegistration(userIdentifier, deviceIdentifier);
    return Response.noContent().build();
  }

  private static DeviceRegistrationDTO mapDeviceRegistrationEntity(
      final DeviceRegistrationEntity entity) {
    return new DeviceRegistrationDTO(
        entity.getId().getUserIdentifier(),
        entity.getId().getDeviceIdentifier(),
        entity.getCreationTimestamp(),
        DeviceType.valueOf(entity.getDeviceType()));
  }
}
