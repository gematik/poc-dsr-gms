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

import static de.gematik.dsr.gms.application.ios.IOSValidationReason.UNREADABLE_RECEIPT;

import de.gematik.dsr.gms.application.Validation;
import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.cms.CMSTypedData;
import org.jboss.logging.Logger;

/**
 * Collects the Request Attributes Sequences from the signed message payload.
 *
 * @see de.gematik.dsr.gms.application.ios.receipt.IOSReceiptAttribute
 */
class IOSReceiptAttributeCollectingValidation
    implements Validation<CMSTypedData, List<ASN1Sequence>> {

  private static final Logger LOG = Logger.getLogger(IOSReceiptAttributeCollectingValidation.class);

  @Override
  public List<ASN1Sequence> evaluate(CMSTypedData dataToValidate) {
    byte[] content = (byte[]) dataToValidate.getContent();
    final List<ASN1Sequence> attributeSequences = new ArrayList<>();
    try (ASN1InputStream inputStream = new ASN1InputStream(content)) {
      final DLSet attributesSet = (DLSet) inputStream.readObject();
      final Enumeration<ASN1Encodable> attributes = attributesSet.getObjects();
      while (attributes.hasMoreElements()) {
        attributeSequences.add((ASN1Sequence) attributes.nextElement());
      }
    } catch (IOException e) {
      UUID traceId = UUID.randomUUID();
      LOG.errorf(
          "%s - The receipt content is not readable as list of receipt attributes sequences",
          traceId);
      throw new GMServiceRuntimeException(UNREADABLE_RECEIPT, traceId, e);
    }
    return attributeSequences;
  }
}
