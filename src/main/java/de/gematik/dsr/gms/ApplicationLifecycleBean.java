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

package de.gematik.dsr.gms;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

@ApplicationScoped
public class ApplicationLifecycleBean {

  private static final Logger LOG = Logger.getLogger(ApplicationLifecycleBean.class);

  @SuppressWarnings("java:S1172")
  void onStart(@Observes StartupEvent ev) {
    LOG.info("The application is starting...");
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    BrainpoolCurves.init();
    LOG.info("Init BrainpoolCurves done.");
  }
}
