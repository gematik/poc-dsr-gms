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

import static de.gematik.dsr.gms.application.exception.GMServiceExceptionReason.FAIL_ON_RESOURCE_READING;

import de.gematik.dsr.gms.application.exception.GMServiceRuntimeException;
import io.smallrye.jwt.util.ResourceUtils;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

public class ClasspathResourcesReader {

  private static final Logger LOG = Logger.getLogger(ClasspathResourcesReader.class);

  private ClasspathResourcesReader() {}

  public static List<byte[]> readFromClasspathResources(
      final Predicate<String> additionalFileFilter, final String... filePaths) {
    return Arrays.stream(filePaths)
        .filter(additionalFileFilter)
        .map(
            path -> {
              try {
                return ResourceUtils.getResourceStream(path);
              } catch (IOException e) {
                UUID traceId = UUID.randomUUID();
                LOG.errorf(
                    "%s - Can't open input stream from the path '%s': %s",
                    traceId, path, e.getMessage());
                throw new GMServiceRuntimeException(FAIL_ON_RESOURCE_READING, traceId, e);
              }
            })
        .map(
            inputStream -> {
              try {
                return inputStream.readAllBytes();
              } catch (IOException e) {
                UUID traceId = UUID.randomUUID();
                LOG.errorf("%s - Can't read input stream: %s", traceId, e.getMessage());
                throw new GMServiceRuntimeException(FAIL_ON_RESOURCE_READING, traceId, e);
              }
            })
        .toList();
  }

  public static Predicate<String> extensionPathMatcherPredicate(final String... extension) {
    List<Pattern> list =
        Arrays.stream(extension).map(ex -> ".*." + ex + "$").map(Pattern::compile).toList();

    return path ->
        list.stream().anyMatch(pathMatcher -> path != null && pathMatcher.matcher(path).matches());
  }
}
