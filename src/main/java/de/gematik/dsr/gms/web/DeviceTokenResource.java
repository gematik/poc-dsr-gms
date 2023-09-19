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

import de.gematik.dsr.gms.application.DeviceTokenService;
import de.gematik.dsr.gms.web.model.*;
import jakarta.inject.Inject;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/device-token")
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
@Produces(MediaType.APPLICATION_JSON)
public class DeviceTokenResource {

  @Inject DeviceTokenService deviceTokenService;

  @POST
  public Response obtainDeviceToken(
      @FormParam("code") @NotBlank(message = "Missing form parameter") String authCode,
      @FormParam("code_verifier") @NotBlank(message = "Missing form parameter")
          String codeVerifier) {

    final var deviceTokenOptional = deviceTokenService.obtainDeviceToken(authCode, codeVerifier);
    if (deviceTokenOptional.isPresent()) {
      return Response.ok(new DeviceTokenResponse(deviceTokenOptional.get())).build();
    } else {
      return Response.status(Response.Status.ACCEPTED).build();
    }
  }
}
