import allure
import pytest
from experiments1.Vigenere import VigenereCipher


@allure.feature("维吉尼亚密码算法测试")
class TestVigenereCipher:
    @pytest.fixture(autouse=True)
    def setup(self):
        """ 初始化测试环境 """
        self.base_key = "testkey"
        self.cipher = VigenereCipher(self.base_key)
        yield
        # 测试后重置密钥保证隔离性
        self.cipher.set_key(self.base_key)

    @allure.story("基础加密功能验证")
    @pytest.mark.parametrize("plaintext,expected", [
        ("attackatdawn", "txltmoymhspx"),  # 标准军事用例
        ("hello", "aidey"),  # 短文本
        ("a", "t"),  # 单字符
        ("", ""),  # 空文本
        ("python", "iclayr")  # 密钥重复使用
    ], ids=["军事用例", "短文本", "单字符", "空文本", "循环密钥"])
    def test_encryption(self, plaintext, expected):
        """ 验证各种场景下的加密正确性 """
        with allure.step(f"加密明文：{plaintext}"):
            result = self.cipher.encrypt(plaintext)
        with allure.step(f"验证密文：{result} == {expected}"):
            assert result == expected

    @allure.story("基础解密功能验证")
    @pytest.mark.parametrize("ciphertext,expected", [
        ("txltmoymhspx", "attackatdawn"),
        ("aidey", "hello"),
        ("t", "a"),
        ("", "")
    ], ids=["军事用例", "短文本", "单字符", "空文本"])
    def test_decryption(self, ciphertext, expected):
        """ 验证各种场景下的解密正确性 """
        with allure.step(f"解密密文：{ciphertext}"):
            result = self.cipher.decrypt(ciphertext)
        with allure.step(f"验证明文：{result} == {expected}"):
            assert result == expected

    @allure.story("加解密闭环验证")
    @pytest.mark.parametrize("text", [
        "deepseek",
        "artificialintelligence",
        "x" * 20,  # 边界值
        "a"  # 最小长度
    ], ids=["常规文本", "长文本", "重复字符", "单字符"])
    def test_encrypt_decrypt_cycle(self, text):
        """ 验证加密后解密能还原原始文本 """
        with allure.step("执行加密流程"):
            encrypted = self.cipher.encrypt(text)
        with allure.step("执行解密流程"):
            decrypted = self.cipher.decrypt(encrypted)
        with allure.step("验证闭环一致性"):
            assert decrypted == text.lower()

    @allure.story("动态密钥管理测试")
    def test_key_management(self):
        """ 验证密钥更换机制的有效性 """
        original_text = "confidential"

        with allure.step("记录初始密钥状态"):
            initial_key_display = self.cipher.key

        with allure.step("使用初始密钥加密"):
            original_cipher = self.cipher.encrypt(original_text)

        with allure.step("更换新密钥"):
            new_key = "newsecret"
            self.cipher.set_key(new_key)

        with allure.step("验证密钥显示保护"):
            assert len(self.cipher.key) == len(new_key)

        with allure.step("新密钥加密验证"):
            new_cipher = self.cipher.encrypt(original_text)
            assert new_cipher != original_cipher

        with allure.step("恢复原始密钥"):
            self.cipher.set_key(self.base_key)
            restored_cipher = self.cipher.encrypt(original_text)
            assert restored_cipher == original_cipher

    @allure.story("异常处理能力验证")
    def test_special_cases(self):
        """ 验证特殊字符处理逻辑 """
        with allure.step("测试大小写混合输入"):
            mixed_case = "HeLLo"
            assert self.cipher.decrypt(self.cipher.encrypt(mixed_case)) == mixed_case.lower()

        with allure.step("测试包含非字母字符"):
            special_text = "hello!"
            encrypted = self.cipher.encrypt(special_text)
            decrypted = self.cipher.decrypt(encrypted)
            assert decrypted == "helloo"  # 自动过滤非字母字符
