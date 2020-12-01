from bitarray import bitarray


class LZ77Compressor:
    MAX_WINDOW_SIZE = 400

    def __init__(self, window_size=20):
        self.window_size = min(window_size, self.MAX_WINDOW_SIZE)
        self.lookahead_buffer_size = 15  # length of match is at most 4 bits

    def compress(self, data, verbose=False):
        i = 0
        output_buffer = bitarray(endian='big')

        while i < len(data):
            match = self.findLongestMatch(data, i)

            if match:
                # Add 1 bit flag, followed by 12 bit for distance, and 4 bit for the length
                # of the match
                (bestMatchDistance, bestMatchLength) = match

                output_buffer.append(True)
                output_buffer.frombytes(bytes([bestMatchDistance >> 4]))
                output_buffer.frombytes(bytes([((bestMatchDistance & 0xf) << 4) | bestMatchLength]))

                if verbose:
                    print("<1, %i, %i>" % (bestMatchDistance, bestMatchLength), end='')

                i += bestMatchLength

            else:
                # No useful match was found. Add 0 bit flag, followed by 8 bit for the character
                output_buffer.append(False)
                output_buffer.frombytes(bytes([data[i]]))

                if verbose:
                    print("<0, %s>" % data[i], end='')

                i += 1

        # fill the buffer with zeros if the number of bits is not a multiple of 8
        output_buffer.fill()

        # return the compressed data
        return output_buffer

    def decompress(self, data):
        output_buffer = []

        while len(data) >= 9:

            flag = data.pop(0)

            if not flag:
                byte = data[0:8].tobytes()

                output_buffer.append(byte)
                del data[0:8]
            else:
                byte1 = ord(data[0:8].tobytes())
                byte2 = ord(data[8:16].tobytes())

                del data[0:16]
                distance = (byte1 << 4) | (byte2 >> 4)
                length = (byte2 & 0xf)

                for i in range(length):
                    output_buffer.append(output_buffer[-distance])
        out_data = b''.join(output_buffer)

        return out_data

    def findLongestMatch(self, data, current_position):
        """
        Finds the longest match to a substring starting at the current_position
        in the lookahead buffer from the history window
        """
        end_of_buffer = min(current_position + self.lookahead_buffer_size, len(data) + 1)

        best_match_distance = -1
        best_match_length = -1

        # Optimization: Only consider substrings of length 2 and greater, and just
        # output any substring of length 1 (8 bits uncompressed is better than 13 bits
        # for the flag, distance, and length)
        for j in range(current_position + 2, end_of_buffer):

            start_index = max(0, current_position - self.window_size)
            substring = data[current_position:j]

            for i in range(start_index, current_position):

                repetitions = len(substring) // (current_position - i)

                last = len(substring) % (current_position - i)

                matched_string = data[i:current_position] * repetitions + data[i:i + last]

                if matched_string == substring and len(substring) > best_match_length:
                    best_match_distance = current_position - i
                    best_match_length = len(substring)

        if best_match_distance > 0 and best_match_length > 0:
            return (best_match_distance, best_match_length)
        return None


def bitarray2bytes(data):
    return data.tobytes()


def bytes2bitarray(data):
    STR = ''
    for byte in data:
        # 每个byte转为bit
        tmp = int(byte)
        tmp1 = '{:08b}'.format(tmp)
        # print(tmp1)
        STR = STR + tmp1
    return bitarray(STR)  # 输入bitarray格式 返回Bytes格式
#
# compress = LZ77Compressor()
# file_path = "test1.txt"
# f = open(file_path, "rb")
# M = f.read()
# print(M)
# b = compress.compress(M) # 输入bytes格式 返回的是bitarray格式
# b = bitarray2bytes(b)
#
# b = b + bytes(10)
# b = b + bytes([20])
# K = 0x2BD6459F82C5B300952C49104881FF48
# b1 = IDEA.IDEA_en(b, K)
#
# b1 = compress.compress(b1)
# b1 = bitarray2bytes(b1)
#
# c1 = bytes2bitarray(b1)
# c1 = compress.decompress(c1)
# c1 = IDEA.IDEA_de(c1, K)
# c1 = bytes2bitarray(c1)

# c1 = compress.decompress(c1) #输入bitarray格式 返回Bytes格式
# print(c1[:-10])
