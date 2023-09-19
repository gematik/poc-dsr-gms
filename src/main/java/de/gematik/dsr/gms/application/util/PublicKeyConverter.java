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
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.eclipse.microprofile.config.spi.Converter;
import org.jboss.logging.Logger;

@RegisterForReflection
public class PublicKeyConverter implements Converter<PublicKey> {

  private static final Logger LOG = Logger.getLogger(PublicKeyConverter.class);

  private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  @Override
  public PublicKey convert(String publicKeyPath)
      throws IllegalArgumentException, NullPointerException {
    try {
      PemReader pemReader =
          new PemReader(new InputStreamReader(ResourceUtils.getResourceStream(publicKeyPath)));
      final X509EncodedKeySpec keySpec =
          new X509EncodedKeySpec(pemReader.readPemObject().getContent());
      final KeyFactory keyFactory = KeyFactory.getInstance("RSA", BOUNCY_CASTLE_PROVIDER);
      return keyFactory.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
      LOG.errorf(
          "Can't read and convert public key resource under the path: %s to PublicKey",
          publicKeyPath);
      throw new IllegalArgumentException(
          "Failed to convert content under the path: " + publicKeyPath + " to PublicKey", e);
    }
  }
}
