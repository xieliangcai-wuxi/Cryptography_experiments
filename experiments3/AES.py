class AES128:
    # AES常量定义
    S_BOX = [
        # 原S_BOX内容保持不变...
    ]

    MIX_COLUMNS_MATRIX = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    def __init__(self, key):
        """初始化AES-128加密器"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        self.key = self.string_to_state(key)
        self.round_keys = self.key_expansion(key)  # 需要实现密钥扩展

    @staticmethod
    def string_to_state(s):
        """字节数组转4x4状态矩阵[1](@ref)"""
        return [[s[i * 4 + j] for j in range(4)] for i in range(4)]

    @staticmethod
    def state_to_string(state):
        """4x4状态矩阵转字节数组"""
        return [state[i][j] for j in range(4) for i in range(4)]

    def _sub_bytes(self, state):
        """字节代换操作[3](@ref)"""
        return [[self.S_BOX[b] for b in row] for row in state]

    def _shift_rows(self, state):
        """行移位变换[3](@ref)"""
        return [
            state[0],
            state[1][1:] + state[1][:1],
            state[2][2:] + state[2][:2],
            state[3][3:] + state[3][:3]
        ]

    def _gf_multiply(self, a, b):
        """有限域GF(2^8)乘法[5](@ref)"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p

    def _mix_columns(self, state):
        """列混合变换[7](@ref)"""
        new_state = []
        for col in range(4):
            column = [state[row][col] for row in range(4)]
            for row in range(4):
                new_val = 0
                for i in range(4):
                    new_val ^= self._gf_multiply(
                        self.MIX_COLUMNS_MATRIX[row][i],
                        column[i]
                    )
                new_state.append(new_val)
        return self.string_to_state(new_state)

    def encrypt_block(self, plaintext):
        """加密单个16字节块"""
        state = self.string_to_state(plaintext)

        # 初始轮密钥加[1](@ref)
        state = self._add_round_key(state, self.round_keys[0])

        # 9轮常规轮
        for round in range(1, 10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round])

        # 最终轮
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[10])

        return self.state_to_string(state)

    def _add_round_key(self, state, round_key):
        """轮密钥加[5](@ref)"""
        return [[state[i][j] ^ round_key[i][j]
                 for j in range(4)] for i in range(4)]

    def key_expansion(self, key):
        """密钥扩展（需完整实现）"""
        # 这里需要实现完整的密钥扩展算法
        # 返回包含11个轮密钥的列表
        return [key] * 11  # 示例代码，实际需要完整实现


# 使用示例
if __name__ == "__main__":
    # 示例数据（16字节）
    plaintext = [0x57, 0x41, 0x4e, 0x47, 0x32, 0x45, 0x52, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07]
    key = [0x32, 0x30, 0x31, 0x33, 0x31, 0x32, 0x32, 0x30,
           0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06]

    # 创建AES实例
    aes = AES128(key)

    # 执行加密
    ciphertext = aes.encrypt_block(plaintext)
    print("加密结果:", [hex(b) for b in ciphertext])