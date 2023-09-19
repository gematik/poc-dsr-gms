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

import static de.gematik.dsr.gms.application.android.integrityverdict.validation.IntegrityVerdictValidation.IntegrityVerdictValidationInitializationReason.FAILED_TO_READ_DECODE_INTEGRITY_RESPONSE;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.playintegrity.v1.PlayIntegrity;
import com.google.api.services.playintegrity.v1.PlayIntegrityRequestInitializer;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenRequest;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenResponse;
import com.google.api.services.playintegrity.v1.model.TokenPayloadExternal;
import com.google.auth.Credentials;
import com.google.auth.http.HttpCredentialsAdapter;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdict;
import de.gematik.dsr.gms.application.android.integrityverdict.IntegrityVerdictGoogleClient;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import io.quarkus.arc.lookup.LookupIfProperty;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
@LookupIfProperty(name = "android.play-integrity-api-client.enabled", stringValue = "true")
public class PlayIntegrityApiClient implements IntegrityVerdictGoogleClient {

  private static final Logger LOG = Logger.getLogger(PlayIntegrityApiClient.class);

  private final PlayIntegrity playIntegrity;

  private final ObjectMapper objectMapper;

  public PlayIntegrityApiClient(
      @ConfigProperty(name = "android.integrity-verdict.root-url") Optional<String> rootUrl,
      @ConfigProperty(name = "android.integrity-verdict.application-name") String applicationName,
      final Credentials googleCredentials,
      final ObjectMapper objectMapper) {
    this.playIntegrity = initializePlayIntegrity(rootUrl, applicationName, googleCredentials);
    this.objectMapper = objectMapper;
  }

  @Override
  public IntegrityVerdict.TokenPayloadExternal decodeIntegrityToken(
      String packageName, String integrityToken) {
    DecodeIntegrityTokenRequest decodeIntegrityTokenRequest = new DecodeIntegrityTokenRequest();
    decodeIntegrityTokenRequest.setIntegrityToken(integrityToken);

    try {
      final DecodeIntegrityTokenResponse response =
          playIntegrity
              .v1()
              .decodeIntegrityToken(packageName, decodeIntegrityTokenRequest)
              .execute();

      TokenPayloadExternal tokenPayloadExternal = response.getTokenPayloadExternal();
      return objectMapper.convertValue(
          tokenPayloadExternal, IntegrityVerdict.TokenPayloadExternal.class);
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf("%s Error while reading response from play integrity api", traceId);
      throw new GMServiceRuntimeException(FAILED_TO_READ_DECODE_INTEGRITY_RESPONSE, traceId, e);
    }
  }

  private PlayIntegrity initializePlayIntegrity(
      Optional<String> rootUrl, final String applicationName, final Credentials credentials) {
    final HttpRequestInitializer httpRequestInitializer = new HttpCredentialsAdapter(credentials);
    final HttpTransport httpTransport =
        new ApacheHttpTransport(); // TODO: add config properties, if necessary
    final JsonFactory jsonFactory = new GsonFactory();

    PlayIntegrity.Builder builder =
        new PlayIntegrity.Builder(httpTransport, jsonFactory, httpRequestInitializer)
            .setPlayIntegrityRequestInitializer(new PlayIntegrityRequestInitializer());
    builder = Optional.ofNullable(applicationName).map(builder::setApplicationName).orElse(builder);
    builder = rootUrl.map(builder::setRootUrl).orElse(builder);

    return builder.build();
  }
}
