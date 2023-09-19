/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.dsr.gms.application.util;

import de.gematik.idp.crypto.CryptoLoader;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.smallrye.jwt.util.ResourceUtils;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import org.eclipse.microprofile.config.spi.Converter;

@RegisterForReflection
public class X509CertificateConverter implements Converter<X509Certificate> {

  @Override
  public X509Certificate convert(final String certificatePath) {
    try {
      InputStream certInputStream = ResourceUtils.getResourceStream(certificatePath);
      return CryptoLoader.getCertificateFromPem(certInputStream.readAllBytes());
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Failed to convert certificatePath into X509Certificate", e);
    }
  }
}
