class PlayfairCipher:
    """Playfair密码加解密类"""

    _CLASS_LETTERS = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # 固定字母表(I/J合并)

    def __init__(self, key: str):
        """
        初始化密码实例
        :param key: 加密密钥（区分大小写）
        """
        self.key = self._preprocess_key(key)
        self.matrix = self._generate_matrix()

    def _preprocess_key(self, key: str) -> str:
        """密钥预处理：转大写、去重、替换J为I"""
        key = key.upper().replace('J', 'I')
        seen = set()
        return ''.join([ch for ch in key if ch not in seen and not seen.add(ch)])

    def _generate_matrix(self) -> list[list[str]]:
        """生成5x5密码矩阵"""
        # 合并密钥与字母表
        key_chars = self.key + ''.join(ch for ch in self._CLASS_LETTERS if ch not in self.key)
        # 构建矩阵
        return [key_chars[i * 5: (i + 1) * 5] for i in range(5)]

    def _find_position(self, char: str) -> tuple[int, int]:
        """查找字符在矩阵中的位置"""
        for row_idx, row in enumerate(self.matrix):
            if char in row:
                return (row_idx, row.index(char))
        raise ValueError(f"字符 {char} 不在密码矩阵中")

    def _encrypt_pair(self, pair: str) -> str:
        """加密字符对"""
        (r1, c1), (r2, c2) = self._find_position(pair[0]), self._find_position(pair[1])

        if r1 == r2:  # 同行
            return self.matrix[r1][(c1 + 1) % 5] + self.matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # 同列
            return self.matrix[(r1 + 1) % 5][c1] + self.matrix[(r2 + 1) % 5][c2]
        else:  # 矩形规则
            return self.matrix[r1][c2] + self.matrix[r2][c1]

    def _decrypt_pair(self, pair: str) -> str:
        """解密字符对"""
        (r1, c1), (r2, c2) = self._find_position(pair[0]), self._find_position(pair[1])

        if r1 == r2:  # 同行
            return self.matrix[r1][(c1 - 1) % 5] + self.matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:  # 同列
            return self.matrix[(r1 - 1) % 5][c1] + self.matrix[(r2 - 1) % 5][c2]
        else:  # 矩形规则
            return self.matrix[r1][c2] + self.matrix[r2][c1]

    def _prepare_plaintext(self, text: str) -> list[str]:
        """明文预处理：转大写、去空格、替换J、处理重复字母"""
        text = text.upper().replace('J', 'I').replace(' ', '')
        # 新增有效性检查
        invalid_chars = [ch for ch in text if ch not in self._CLASS_LETTERS]
        if invalid_chars:
            raise ValueError(f"包含无效字符: {set(invalid_chars)}")
        processed = []
        i = 0
        while i < len(text):
            if i == len(text) - 1 or text[i] == text[i + 1]:
                processed.append(text[i] + 'X')
                i += 1
            else:
                processed.append(text[i] + text[i + 1])
                i += 2
        return processed

    def encrypt(self, plaintext: str) -> str:
        """加密明文"""
        pairs = self._prepare_plaintext(plaintext)
        return ''.join([self._encrypt_pair(pair) for pair in pairs])

    def decrypt(self, ciphertext: str) -> str:
        """解密密文"""
        ciphertext = ciphertext.upper().replace(' ', '')
        if len(ciphertext) % 2 != 0:
            raise ValueError("密文长度必须为偶数")

        pairs = [ciphertext[i:i + 2] for i in range(0, len(ciphertext), 2)]
        decrypted = ''.join([self._decrypt_pair(pair) for pair in pairs])

        # 移除填充的X（保留末尾的X）
        clean_text = []
        for i in range(len(decrypted)):
            if decrypted[i] != 'X' or (i > 0 and i < len(decrypted) - 1 and decrypted[i - 1] == decrypted[i + 1]):
                clean_text.append(decrypted[i])
        return ''.join(clean_text).lower()


# 使用示例
if __name__ == "__main__":
    key = input("请输入密钥：")
    cipher = PlayfairCipher(key)

    plaintext = input("明文：")
    encrypted = cipher.encrypt(plaintext)
    print(f"加密结果：{encrypted}")

    decrypted = cipher.decrypt(encrypted)
    print(f"解密结果：{decrypted}")
