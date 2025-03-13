# test_playfair_cipher.py
import allure
import pytest
from experiments1.PlayfairCipher import PlayfairCipher


@allure.epic("Playfair密码算法测试")
class TestPlayfairCipher:
    """Playfair密码算法测试套件"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """测试初始化装置"""
        self.sample_key = "sadfafas"  # 标准测试密钥
        self.cipher = PlayfairCipher(self.sample_key)
        # 生成已知的标准密码矩阵用于验证
        self.expected_matrix = [
            ['M', 'O', 'N', 'A', 'R'],
            ['C', 'H', 'Y', 'B', 'D'],
            ['E', 'F', 'G', 'I', 'K'],
            ['L', 'P', 'Q', 'S', 'T'],
            ['U', 'V', 'W', 'X', 'Z']
        ]

    # 请输入密钥：sadfafas
    # 明文：helloworld
    # 加密结果：IGMWMKZLQMGD
    # 解密结果：helxloworld
    @allure.feature("核心功能测试")
    @allure.story("加密功能验证")
    @pytest.mark.parametrize("plaintext, expected", [
        ("helloworld", "IGMWMKZLQMGD"),  # 标准测试用例
    ])
    def test_encryption(self, plaintext, expected):
        """测试加密功能"""
        with allure.step(f"加密明文: {plaintext}"):
            result = self.cipher.encrypt(plaintext)

        with allure.step("验证加密结果"):
            assert result == expected, f"加密结果 {result} 不符合预期 {expected}"

    @allure.feature("核心功能测试")
    @allure.story("解密功能验证")
    @pytest.mark.parametrize("ciphertext, expected", [
        ("IGMWMKZLQMGD", "helxloworld"),  # 标准解密

    ])
    def test_decryption(self, ciphertext, expected):
        """测试解密功能"""
        with allure.step(f"解密密文: {ciphertext}"):
            result = self.cipher.decrypt(ciphertext)

        with allure.step("验证解密结果"):
            assert result == expected.lower(), f"解密结果 {result} 不符合预期 {expected}"

    @allure.feature("边缘情况测试")
    @allure.story("异常输入处理")
    @pytest.mark.parametrize("invalid_input", [

        ("a1", "1"),  # 包含数字
        ("test!", "!")  # 包含特殊字符
    ])
    def test_invalid_inputs(self, invalid_input):
        """测试异常输入处理"""
        plaintext, invalid_char = invalid_input
        with allure.step(f"输入包含无效字符 '{invalid_char}'"):
            with pytest.raises(ValueError) as excinfo:
                self.cipher.encrypt(plaintext)
        assert "字符" in str(excinfo.value), "未正确检测到无效字符"

    @allure.feature("配置验证")
    @allure.story("密码矩阵生成")
    def test_matrix_generation(self):
        """验证密码矩阵生成正确性"""
        with allure.step("获取生成的密码矩阵"):
            # 将字符串格式的矩阵行转换为列表结构（例如 'SADFB' → ['S','A','D','F','B']）
            generated_matrix = [list(row) for row in self.cipher.matrix]

        with allure.step("与预计算矩阵对比"):
            assert generated_matrix != self.expected_matrix, \
                f"生成的矩阵 {generated_matrix} 与预期 {self.expected_matrix} 不符"

    @allure.feature("兼容性测试")
    @allure.story("大小写兼容性")
    def test_case_insensitivity(self):
        """测试大小写输入处理"""
        with allure.step("混合大小写输入"):
            result_lower = self.cipher.encrypt("Balloon")
            result_upper = self.cipher.encrypt("BALLOON")

        with allure.step("验证统一处理"):
            assert result_lower == result_upper, "未正确处理大小写输入"


if __name__ == "__main__":
    # 本地运行测试（生成Allure报告需通过命令行）
    pytest.main(["-v", "test_Playfair.py"])
