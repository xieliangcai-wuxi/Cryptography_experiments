class VigenereCipher:
    def __init__(self, key: str):
        self._key = key.lower()  # 统一转换为小写
        self._ord_a = ord('a')

    def encrypt(self, plaintext: str) -> str:
        """ 加密明文 """
        ciphertext = []
        key_len = len(self._key)
        for i, char in enumerate(plaintext.lower()):
            # 计算偏移量：明文字符 + 密钥字符
            shift = ord(self._key[i % key_len]) - self._ord_a
            encrypted_char = chr((ord(char) - self._ord_a + shift) % 26 + self._ord_a)
            ciphertext.append(encrypted_char)
        return ''.join(ciphertext)

    def decrypt(self, ciphertext: str) -> str:
        """ 解密密文 """
        plaintext = []
        key_len = len(self._key)
        for i, char in enumerate(ciphertext.lower()):
            # 计算偏移量：密文字符 - 密钥字符
            shift = ord(self._key[i % key_len]) - self._ord_a
            decrypted_char = chr((ord(char) - self._ord_a - shift) % 26 + self._ord_a)
            plaintext.append(decrypted_char)
        return ''.join(plaintext)

    def set_key(self, new_key: str):
        """ 更新密钥 """
        self._key = new_key.lower()

    @property
    def key(self):
        """ 获取当前密钥（安全返回） """
        return '*' * len(self._key)  # 实际应用应加密存储


if __name__ == '__main__':
    # 实例化密码机（初始密钥为python）
    cipher = VigenereCipher("python")

    # 原始消息
    original_text = "deepseek"
    print(f"原始明文: {original_text}")

    # 加密演示
    encrypted = cipher.encrypt(original_text)
    print(f"加密结果: {encrypted}")

    # 解密演示
    decrypted = cipher.decrypt(encrypted)
    print(f"解密结果: {decrypted}")



    # 新密钥加解密验证
    new_encrypted = cipher.encrypt(original_text)
    print(f"\n新密钥加密: {new_encrypted}")
    print(f"新密钥解密: {cipher.decrypt(new_encrypted)}")


