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
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.*;

/** Validation for the certificate chain. */
public class CertificateChainValidation
    implements Validation<List<X509Certificate>, List<X509Certificate>> {

  private final PublicKey rootPublicKey;
  private final Validation<X509Certificate, X509Certificate> chainRootCertificateVerifier;
  private final Clock clock;

  /**
   * Creates the new instance of {@link CertificateChainValidation}.
   *
   * @param rootPublicKey - the public key of the root certificate, for Example Google or Apple
   * @param rootCertificateVerifier - additional check for root certificate, if any necessary
   * @param clock - clock for certificate expiration validation
   */
  public CertificateChainValidation(
      PublicKey rootPublicKey,
      Validation<X509Certificate, X509Certificate> rootCertificateVerifier,
      Clock clock) {
    this.rootPublicKey = Objects.requireNonNull(rootPublicKey);
    this.chainRootCertificateVerifier = rootCertificateVerifier;
    this.clock = clock;
  }

  /**
   * Creates the new instance of {@link CertificateChainValidation}.
   *
   * @param rootCertificate - the root certificate, for Example Google or Apple
   * @param rootCertificateVerifier - additional check for root certificate, if any necessary
   * @param clock - clock for certificate expiration validation
   */
  public CertificateChainValidation(
      X509Certificate rootCertificate,
      Validation<X509Certificate, X509Certificate> rootCertificateVerifier,
      Clock clock) {
    this(rootCertificate.getPublicKey(), rootCertificateVerifier, clock);
  }

  /**
   * Verifies the chain from the end, which should be a root to begin, which is a leaf certificate.
   * Last certificate inside of chain should be signed by the given instance {@link #rootPublicKey}
   * and the intermediates by the public key of the next neighbour
   *
   * @param dataToValidate certificate chain to be verified.
   * @return the same as the input, if no validation errors
   * @throws GMServiceRuntimeException occurs if the chain is invalid or expired
   */
  @Override
  public List<X509Certificate> evaluate(List<X509Certificate> dataToValidate) {
    final List<X509Certificate> reversedChain = new ArrayList<>(dataToValidate);
    Collections.reverse(reversedChain);
    X509Certificate currentParent = reversedChain.get(0);
    verifyCertificate(currentParent, rootPublicKey);
    currentParent = chainRootCertificateVerifier.evaluate(currentParent);
    for (int index = 1; index < reversedChain.size(); index++) {
      X509Certificate x509Certificate = reversedChain.get(index);
      verifyCertificate(x509Certificate, currentParent.getPublicKey());
      currentParent = x509Certificate;
    }
    return dataToValidate;
  }

  private void verifyCertificate(X509Certificate certificate, PublicKey publicKey) {
    try {
      certificate.checkValidity(new Date(clock.millis()));
      certificate.verify(publicKey);
    } catch (CertificateException
        | NoSuchAlgorithmException
        | InvalidKeyException
        | NoSuchProviderException
        | SignatureException e) {
      throw new GMServiceRuntimeException(
          ValidationExceptionReason.INVALID_CERTIFICATE_CHAIN, UUID.randomUUID(), e);
    }
  }
}
