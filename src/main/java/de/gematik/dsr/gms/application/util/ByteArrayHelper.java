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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ByteArrayHelper {

  private ByteArrayHelper() {
    // Utility Class
  }

  public static byte[] concatArrays(byte[]... arrays) {
    Integer commonLength =
        Arrays.stream(arrays).map(bytes -> bytes.length).reduce(Integer::sum).orElse(0);

    byte[] concatenatedArray = new byte[commonLength];
    ByteBuffer byteBuffer = ByteBuffer.allocate(commonLength);
    Arrays.stream(arrays).forEachOrdered(byteBuffer::put);
    byteBuffer.flip().get(concatenatedArray);

    return concatenatedArray;
  }

  public static boolean compareByteArrayLists(List<byte[]> one, List<byte[]> another) {
    if (one == null && another == null) {
      return true;
    }
    if (one != null && one.isEmpty() && another != null && another.isEmpty()) {
      return true;
    }

    if (one != null && another != null) {
      return one.size() == another.size()
          && IntStream.of(0, one.size() - 1)
              .allMatch(index -> Arrays.equals(one.get(index), another.get(index)));
    }
    return false;
  }

  public static String toStringByteArrayList(List<byte[]> bytes) {
    if (bytes == null) {
      return null;
    }
    return '[' + bytes.stream().map(Arrays::toString).collect(Collectors.joining(",")) + ']';
  }
}
