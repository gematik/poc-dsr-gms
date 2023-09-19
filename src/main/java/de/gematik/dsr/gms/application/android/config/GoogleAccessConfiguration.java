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

package de.gematik.dsr.gms.application.android.config;

import static de.gematik.dsr.gms.application.exception.GMServiceExceptionReason.FAILED_TO_LOAD_GOOGLE_CREDENTIALS;

import com.google.api.services.playintegrity.v1.PlayIntegrityScopes;
import com.google.auth.Credentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.smallrye.jwt.util.ResourceUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Dependent;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@Dependent
public class GoogleAccessConfiguration {

  private static final Logger LOG = Logger.getLogger(GoogleAccessConfiguration.class);

  @ApplicationScoped
  @UnlessBuildProfile("test")
  public Credentials googleCredentials(
      @ConfigProperty(name = "android.integrity-verdict.credentials-path")
          final String credentialsTemplatePath,
      @ConfigProperty(name = "android.integrity-verdict.credentials-scope", defaultValue = "false")
          boolean scope) {
    try {
      InputStream resourceAsStream = ResourceUtils.getResourceStream(credentialsTemplatePath);
      GoogleCredentials accountCredentials =
          ServiceAccountCredentials.fromStream(resourceAsStream)
              .createWithUseJwtAccessWithScope(scope);

      if (scope) {
        accountCredentials = accountCredentials.createScoped(PlayIntegrityScopes.all());
      }
      return accountCredentials;
    } catch (IOException e) {
      final UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s Error loading Google credentials from path %s", traceId, credentialsTemplatePath);
      throw new GMServiceRuntimeException(FAILED_TO_LOAD_GOOGLE_CREDENTIALS, traceId, e);
    }
  }
}
