import pytest
from experiments3.AES import AES128


class TestAES128:
    def test_key_length(self):
        with pytest.raises(ValueError):
            AES128(bytes(15))  # 验证密钥长度校验

    def test_initial_round(self):
        """测试初始轮密钥加（修正后）"""
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        aes = AES128(key)

        expected = bytes.fromhex("00112233445566778899aabbccddeeff")  # 密钥与明文异或结果
        state = aes._add_round_key(aes.string_to_state(plain), aes.key)
        assert aes.state_to_string(state) == list(expected)

    @pytest.fixture
    def sample_state(self):
        return [
            [0x32, 0x88, 0x31, 0xe0],
            [0x43, 0x5a, 0x31, 0x37],
            [0xf6, 0x30, 0x98, 0x07],
            [0xa8, 0x8d, 0xa2, 0x34]
        ]

    def test_sub_bytes(self, sample_state):
        """测试字节代换（修正类方法调用）"""
        transformed = AES128._sub_bytes(sample_state)  # 正确调用类方法
        assert transformed[0][0] == 0x23  # 0x32经S盒转换后的正确值

    def test_shift_rows(self, sample_state):
        """测试行移位（修正类方法调用）"""
        shifted = AES128._shift_rows(sample_state)
        assert shifted[1] == [0x5a, 0x31, 0x37, 0x43]  # 第1行左移1位

    def test_mix_columns(self):
        """测试列混合（使用标准测试向量）"""
        input_state = [
            [0xdb, 0xf2, 0x01, 0xc6],
            [0x13, 0x0a, 0x01, 0xc6],
            [0x53, 0x22, 0x01, 0xc6],
            [0x45, 0x5c, 0x01, 0xc6]
        ]
        expected_output = [
            0x8e, 0x9f, 0x01, 0xc6,  # 第1列混合结果
            0x4d, 0xdc, 0x01, 0xc6,  # 第2列混合结果
            0x7e, 0x47, 0x01, 0xc6,  # 第3列混合结果
            0xa6, 0x8c, 0x01, 0xc6  # 第4列混合结果
        ]
        mixed = AES128._mix_columns(input_state)
        assert AES128.state_to_string(mixed) == expected_output