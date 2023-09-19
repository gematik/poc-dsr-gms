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

package de.gematik.dsr.gms.application.validation;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.util.CertificateAndKeysDataConverter;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.cert.X509Certificate;
import java.util.List;

/** Validation for list of Base64 encoded strings, which should be a certificate chain */
public class CertificateDecryptValidation
    implements Validation<List<String>, List<X509Certificate>> {

  /**
   * Maps list of Base64 encoded strings to list of {@link X509Certificate}s.
   *
   * @param dataToValidate data to be verified and converted.
   * @return list of {@link X509Certificate}s, read from the given strings.
   *     <p>throws {@link GMServiceRuntimeException} occurs if strings are wrong encoded or not
   *     parsable to {@link X509Certificate}s
   */
  @Override
  public List<X509Certificate> evaluate(List<String> dataToValidate) {
    try {
      return CertificateAndKeysDataConverter.decodePemCertificateChain(dataToValidate);
    } catch (IdpCryptoException e) {
      throw new GMServiceRuntimeException(ValidationExceptionReason.NOT_PARSABLE_CERTIFICATE_CHAIN);
    }
  }
}
