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

import de.gematik.dsr.gms.application.RegisterDeviceService;
import de.gematik.dsr.gms.web.model.RegisterDeviceRequestDTO;
import de.gematik.dsr.gms.web.model.RegisterDeviceResponseDTO;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/register-device")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class RegisterDeviceResource {
  @Inject RegisterDeviceService registerDeviceService;

  @POST
  public Response registerDevice(
      @Valid @NotNull(message = "The request body may not be empty")
          final RegisterDeviceRequestDTO dto) {
    return this.handleRegisterDevice(dto);
  }

  private Response handleRegisterDevice(final RegisterDeviceRequestDTO dto) {
    final var serviceResponse = registerDeviceService.registerDevice(dto.token());
    final var resultDTO = new RegisterDeviceResponseDTO(serviceResponse);
    return Response.status(Response.Status.CREATED).entity(resultDTO).build();
  }
}
