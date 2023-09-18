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

package de.gematik.dsr.gms.application.util;

import io.quarkus.runtime.annotations.RegisterForReflection;
import io.smallrye.jwt.util.ResourceUtils;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.eclipse.microprofile.config.spi.Converter;

@RegisterForReflection
public class PrivateKeyConverter implements Converter<PrivateKey> {

  @Override
  public PrivateKey convert(final String keyPath) {
    try {
      final InputStreamReader reader =
          new InputStreamReader(ResourceUtils.getResourceStream(keyPath));
      PEMKeyPair pemKeyPair = (PEMKeyPair) new PEMParser(reader).readObject();

      // convert PEM bytes to PrivateKeyInfo
      final PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();

      PKCS8EncodedKeySpec pkcs8EncodedKeySpec =
          new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());

      final KeyFactory keyFactory = KeyFactory.getInstance("EC");
      return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to convert PrivateKey from key path", e);
    }
  }
}
