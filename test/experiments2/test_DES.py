# test_des.py
import pytest
import allure
from experiments2.DES import DES


@allure.epic("DES加密算法测试")
class TestDES:
    # 标准测试用例（来自NIST测试向量）
    @allure.feature("标准加密测试")
    @pytest.mark.parametrize("key, plaintext, ciphertext", [
        ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),  # 全零测试
        ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),  # 全F测试
        ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),  # 经典测试用例
        ("38627974656B6579", "6D6573736167652E", "7CF45E129445D451")  # ASCII字符测试
    ])
    def test_standard_encrypt(self, key, plaintext, ciphertext):
        """验证标准加密测试向量"""
        with allure.step(f"使用密钥 {key} 加密明文 {plaintext}"):
            des = DES(key)
            result = des.encrypt(plaintext)
            print(f"密文: {result}")

        with allure.step(f"验证密文匹配 {ciphertext}"):
            assert result == ciphertext.upper()

    @allure.feature("加解密可逆性测试")
    @pytest.mark.parametrize("key, data", [
        ("AABB09182736CCDD", "1234567890ABCDEF"),
        ("B0B1B2B3B4B5B6B7", "FEDCBA0987654321"),
        ("0000000000000000", "FFFFFFFFFFFFFFFF"),
        ("FFFFFFFFFFFFFFFF", "0000000000000000")
    ])
    def test_encrypt_decrypt(self, key, data):
        """验证加密后解密能恢复原文"""
        with allure.step("初始化DES实例"):
            des = DES(key)

        with allure.step("执行加密-解密流程"):
            encrypted = des.encrypt(data)
            decrypted = des.decrypt(encrypted)

        with allure.step("验证解密结果匹配原文"):
            assert decrypted == data.upper()

    @allure.feature("异常输入测试")
    @pytest.mark.parametrize("invalid_input, test_type", [
        ("123", "key"),  # 密钥长度不足
        ("GHTYUIJKLMNBVFR6", "key"),  # 非十六进制密钥

    ])
    def test_invalid_inputs(self, invalid_input, test_type):
        """验证异常输入处理"""
        with allure.step("根据测试类型执行不同操作"):
            if test_type == "key":
                with pytest.raises(ValueError) as excinfo:
                    DES(invalid_input)
                assert "invalid key" in str(excinfo.value).lower()

            elif test_type == "short_plain":
                des = DES("0000000000000000")
                with pytest.raises(ValueError):
                    des.encrypt(invalid_input)

            elif test_type == "invalid_char":
                des = DES("0000000000000000")
                with pytest.raises(ValueError):
                    des.encrypt(invalid_input)

    @allure.feature("边界条件测试")
    def test_boundary_conditions(self):
        """验证特殊边界情况"""
        with allure.step("测试全零加密"):
            des = DES("0000000000000000")
            cipher = des.encrypt("0000000000000000")
            assert cipher == "8CA64DE9C1B123A7"

        with allure.step("测试全F加密"):
            des = DES("FFFFFFFFFFFFFFFF")
            cipher = des.encrypt("FFFFFFFFFFFFFFFF")
            assert cipher == "7359B2163E4EDC58"

    @allure.feature("算法特性测试")
    def test_algorithm_properties(self):
        """验证DES算法特性"""
        with allure.step("测试相同输入不同密钥结果不同"):
            des1 = DES("1111111111111111")
            des2 = DES("2222222222222222")
            plain = "0123456789ABCDEF"
            assert des1.encrypt(plain) != des2.encrypt(plain)

        with allure.step("测试相同密钥不同输入结果不同"):
            des = DES("1234567890ABCDEF")
            plain1 = "0000000000000000"
            plain2 = "0000000000000001"
            assert des.encrypt(plain1) != des.encrypt(plain2)


# conftest.py（配置allure环境）
"""
def pytest_configure(config):
    config.addinivalue_line("markers", "security: security tests")
"""