import numpy as np


class HillCipher:
    def __init__(self, K, m=256):

        self.K = K.astype(np.int64)  # 加密密钥
        self.m = m  # 模数
        self.k = None  # 解密密钥
        self.row = K.shape[0]  # 矩阵维度
        self._init_decrypt_key()  # 初始化时计算解密密钥

    def _multi_inverse(self, x):
        """计算模m下的乘法逆元（私有方法）"""
        for y in range(self.m):
            if (x * y) % self.m == 1:
                return y
        raise ValueError(f"{x}在模{self.m}下不存在乘法逆元")

    def _adjoint_mat(self, K_det):
        """计算伴随矩阵（私有方法）"""
        K_inv = np.linalg.inv(self.K)
        K_adj = (K_inv * K_det).round().astype(np.int64) % self.m
        return K_adj

    def _init_decrypt_key(self):
        """初始化解密密钥（私有方法）"""
        K_det = round(np.linalg.det(self.K))
        inv_det = self._multi_inverse(K_det % self.m)
        self.k = (inv_det * self._adjoint_mat(K_det)) % self.m

    def _text_to_matrix(self, text):
        """将文本转换为ASCII矩阵（私有方法）"""
        padding = (-len(text)) % self.row
        text += '\0' * padding  # 填充空字符对齐矩阵维度

        matrix = [ord(c) for c in text]
        return np.array(matrix, dtype=np.int64).reshape(-1, self.row).T % self.m

    def _matrix_to_text(self, matrix):
        """将矩阵转换为文本（私有方法）"""
        matrix = matrix.T.reshape(-1)
        return ''.join(chr(n % self.m) for n in matrix).rstrip('\0')

    def encrypt(self, plaintext):
        """加密方法"""
        m1 = self._text_to_matrix(plaintext)
        m2 = (self.K @ m1) % self.m
        return self._matrix_to_text(m2)

    def decrypt(self, ciphertext):
        """解密方法"""
        m2 = self._text_to_matrix(ciphertext)
        m3 = (self.k @ m2) % self.m
        return self._matrix_to_text(m3)


if __name__ == "__main__":
    # 使用示例
    K = np.array([[17, 17, 5], [21, 18, 21], [2, 2, 19]])
    cipher = HillCipher(K, m=256)

    plaintext = 'Programming is a happy thing'

    print("原始明文:", plaintext)

    ciphertext = cipher.encrypt(plaintext)

    print("加密结果:")
    print(ciphertext)
    decrypted = cipher.decrypt(ciphertext)
    print("解密结果:", decrypted)
