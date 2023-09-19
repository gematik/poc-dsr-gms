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

package de.gematik.dsr.gms.application.ios.receipt.validation;

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.*;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import de.gematik.dsr.gms.application.ios.receipt.IOSReceipt;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.StoreException;
import org.jboss.logging.Logger;

/**
 * Provides parse function of the receipt bytes to the instance of PKCS #7 container, verifies the
 * signature of the parsed message and converts payload to the {@link IOSReceipt} according to the
 * <a
 * href="https://developer.apple.com/documentation/devicecheck/assessing_fraud_risk#3579378">description</a>
 *
 * @see IOSReceipt
 */
class IOSReceiptBytesToSignedDataValidation
    implements Validation<byte[], IOSReceiptBytesToSignedDataValidation.SignedData> {

  private static final Logger LOG = Logger.getLogger(IOSReceiptBytesToSignedDataValidation.class);
  private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  private final IOSReceiptAttributeCollectingValidation dataContentValidation;
  private final JcaSimpleSignerInfoVerifierBuilder verifierBuilder;
  private final JcaX509CertificateConverter x509CertificateConverter;

  IOSReceiptBytesToSignedDataValidation() {
    this.dataContentValidation = new IOSReceiptAttributeCollectingValidation();
    this.verifierBuilder =
        new JcaSimpleSignerInfoVerifierBuilder().setProvider(BOUNCY_CASTLE_PROVIDER);
    x509CertificateConverter = new JcaX509CertificateConverter();
  }

  @Override
  public SignedData evaluate(byte[] dataToValidate) {
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(dataToValidate)) {
      ContentInfo contentInfo = ContentInfo.getInstance(asn1InputStream.readObject());
      CMSSignedData cmsSignedData = new CMSSignedData(contentInfo);
      List<X509Certificate> x509Certificates = verifyCertificates(cmsSignedData);
      verifySignature(cmsSignedData, x509Certificates.get(0));
      IOSReceipt iosReceipt = verifyPayload(cmsSignedData);
      return new SignedData(x509Certificates, iosReceipt);
    } catch (IOException | CMSException e) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s - The receipt information is not readable as signed content instance of: %s",
          traceId, CMSSignedData.class.getSimpleName());
      throw new GMServiceRuntimeException(UNREADABLE_RECEIPT, traceId, e);
    }
  }

  private List<X509Certificate> verifyCertificates(CMSSignedData cmsSignedData) {
    try {
      return cmsSignedData.getCertificates().getMatches(null).stream()
          .map(
              x509CertificateHolder -> {
                try {
                  return x509CertificateConverter.getCertificate(x509CertificateHolder);
                } catch (CertificateException e) {
                  throw new GMServiceRuntimeException(
                      INVALID_PKCS7_CERTIFICATES,
                      UUID.randomUUID(),
                      "The receipt certificates can't be parsed");
                }
              })
          .toList();
    } catch (StoreException e) {
      throw new GMServiceRuntimeException(
          INVALID_PKCS7_CERTIFICATES,
          UUID.randomUUID(),
          "The receipt certificates can't be matched without any selector");
    }
  }

  void verifySignature(CMSSignedData cmsSignedData, X509Certificate firstCertificate) {
    List<SignerInformation> signers = new ArrayList<>(cmsSignedData.getSignerInfos().getSigners());
    if (signers.size() != 1 || signers.get(0) == null) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s - The receipt contains either more than one signature or no signature at all",
          traceId);
      throw new GMServiceRuntimeException(INVALID_PKCS7_SIGNATURE, traceId);
    }
    SignerInformation signerInformation = signers.get(0);
    try {
      SignerInformationVerifier signerInformationVerifier = verifierBuilder.build(firstCertificate);
      boolean verified = signerInformation.verify(signerInformationVerifier);
      if (!verified) {
        throw new GMServiceRuntimeException(
            INVALID_PKCS7_SIGNATURE, UUID.randomUUID(), "The receipt signature is invalid");
      }
    } catch (OperatorCreationException | CMSException e) {
      throw new GMServiceRuntimeException(
          INVALID_PKCS7_SIGNATURE, UUID.randomUUID(), "The receipt certificate can't be verified");
    }
  }

  private IOSReceipt verifyPayload(CMSSignedData cmsSignedData) {
    List<ASN1Sequence> asn1Sequences =
        dataContentValidation.evaluate(cmsSignedData.getSignedContent());
    return IOSReceipt.parseToIOSReceipt(asn1Sequences);
  }

  record SignedData(List<X509Certificate> certificateChain, IOSReceipt payload) {}
}
