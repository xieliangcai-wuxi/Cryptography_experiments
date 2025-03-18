import re
class DES:
    """
    DES加密算法实现类
    功能：支持ECB模式的加密/解密，包含密钥管理
    """

    # 初始置换表（IP）
    ip = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # 最终逆置换表（IP^-1）
    _ip = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    # 密钥置换选择1（PC-1）
    pc1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # 密钥置换选择2（PC-2）
    pc2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    # 每轮左移位数表
    shift_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # S盒定义（8个4x16的矩阵）
    s_boxes = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    def __init__(self, key: str):
        """
        初始化DES实例
        :param key: 64位十六进制字符串表示的密钥
        """
        # 新增密钥校验
        if not re.fullmatch(r'^[0-9A-Fa-f]{16}$', key, flags=re.IGNORECASE):
            raise ValueError("Invalid key format (16 hex chars required)")

        self.subkeys = []  # 存储16轮子密钥
        self._generate_subkeys(key)  # 生成子密钥

    def _generate_subkeys(self, key: str):
        """
        生成16轮子密钥
        :param key: 原始密钥（64位十六进制）
        """
        # 将密钥转换为二进制数组
        key_bin = self._hex_to_bin(key)

        # PC-1置换（64位 -> 56位）
        pc1_result = self._permute(key_bin, self.pc1, 56)

        # 分割左右各28位
        left = pc1_result[:28]
        right = pc1_result[28:]

        # 生成16轮子密钥
        for i in range(16):
            # 循环左移
            left = self._left_shift(left, self.shift_table[i])
            right = self._left_shift(right, self.shift_table[i])

            # 合并并PC-2置换（56位 -> 48位）
            combined = left + right
            subkey = self._permute(combined, self.pc2, 48)
            self.subkeys.append(subkey)

    def encrypt(self, plaintext: str) -> str:
        """
        加密方法
        :param plaintext: 64位十六进制明文
        :return: 64位十六进制密文
        """
        return self._process_block(plaintext, is_encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        """
        解密方法
        :param ciphertext: 64位十六进制密文
        :return: 64位十六进制明文
        """
        return self._process_block(ciphertext, is_encrypt=False)

    def _process_block(self, data: str, is_encrypt: bool) -> str:
        """
        处理单个64位数据块
        :param data: 输入数据（十六进制）
        :param is_encrypt: 是否为加密过程
        :return: 处理结果（十六进制）
        """
        # 将输入转换为二进制数组
        bin_data = self._hex_to_bin(data)

        # 初始置换
        permuted = self._permute(bin_data, self.ip, 64)

        # 分割左右各32位
        left = permuted[:32]
        right = permuted[32:]

        # 16轮Feistel网络
        for i in range(16):
            # 加密使用0-15轮密钥，解密使用15-0轮密钥
            subkey = self.subkeys[i if is_encrypt else 15 - i]

            # Feistel函数处理
            new_left = right.copy()
            new_right = self._xor(left, self._feistel(right, subkey))

            left, right = new_left, new_right

        # 合并并最终置换
        combined = right + left
        ciphertext = self._permute(combined, self._ip, 64)

        # 转换为十六进制返回
        return self._bin_to_hex(ciphertext)

    def _feistel(self, right: list, subkey: list) -> list:
        """
        Feistel函数（核心加密函数）
        :param right: 右半部分32位数据
        :param subkey: 48位子密钥
        :return: 32位输出
        """
        # 扩展置换（32位 -> 48位）
        expanded = self._permute(right, [
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
        ], 48)

        # 与子密钥异或
        xored = self._xor(expanded, subkey)

        # S盒替换（48位 -> 32位）
        sbox_result = []
        for i in range(8):
            # 取6位输入
            six_bits = xored[i * 6: (i + 1) * 6]

            # 计算行列索引
            row = (six_bits[0] << 1) + six_bits[5]
            col = (six_bits[1] << 3) + (six_bits[2] << 2) + (six_bits[3] << 1) + six_bits[4]

            # 查S盒并转换为4位二进制
            val = self.s_boxes[i][row][col]
            sbox_result.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])

        # P置换
        return self._permute(sbox_result, [
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        ], 32)

    @staticmethod
    def _permute(input_bits: list, table: list, output_len: int) -> list:
        """
        通用置换函数
        :param input_bits: 输入位列表
        :param table: 置换表
        :param output_len: 输出长度
        :return: 置换后的位列表
        """
        return [input_bits[i - 1] for i in table][:output_len]

    @staticmethod
    def _left_shift(bits: list, n: int) -> list:
        """
        循环左移函数
        :param bits: 输入位列表
        :param n: 移动位数
        :return: 移位后的位列表
        """
        return bits[n:] + bits[:n]

    @staticmethod
    def _xor(a: list, b: list) -> list:
        """
        按位异或操作
        :param a: 第一个位列表
        :param b: 第二个位列表
        :return: 异或结果位列表
        """
        return [x ^ y for x, y in zip(a, b)]

    @staticmethod
    def _hex_to_bin(hex_str: str) -> list:
        """
        将十六进制字符串转换为二进制位列表
        :param hex_str: 十六进制字符串
        :return: 二进制位列表（每个字符4位）
        """
        bin_str = bin(int(hex_str, 16))[2:].zfill(64)
        return [int(bit) for bit in bin_str]

    @staticmethod
    def _bin_to_hex(bit_list: list) -> str:
        """
        将二进制位列表转换为十六进制字符串
        :param bit_list: 二进制位列表
        :return: 十六进制字符串
        """
        # 将位列表转换为二进制字符串
        bin_str = ''.join(str(bit) for bit in bit_list)
        # 转换为十六进制并补零
        return hex(int(bin_str, 2))[2:].upper().zfill(16)


# 测试示例
if __name__ == "__main__":
    # 初始化DES实例（密钥需要是16位十六进制）
    des = DES(key="FFFFFFFFFFFFFFFF")

    # 加密测试
    plaintext = "111"
    cipher = des.encrypt(plaintext)
    print(f"加密结果: {cipher}")

    # 解密测试
    decrypted = des.decrypt(cipher)
    print(f"解密结果: {decrypted}")  # 应返回原文 1111111111111111