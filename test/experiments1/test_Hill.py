import pytest
import allure

# 通过率100%的关键：使用严格模式 + 异常处理
@pytest.mark.strict
class TestDemo:
    @allure.title("验证加法运算")
    @allure.severity(allure.severity_level.CRITICAL)
    @allure.story("基础数学运算")
    def test_addition(self):
        """预期通过的测试用例"""
        with allure.step("执行加法操作"):
            result = 1 + 1
        assert result == 2, "加法运算结果异常"

    @allure.title("验证异常处理")
    @allure.severity(allure.severity_level.NORMAL)
    def test_exception_handling(self):
        """确保异常被正确捕获"""
        with pytest.raises(ZeroDivisionError):
            with allure.step("触发除以零异常"):
                1 / 0

# 通用前置操作（Fixture示例）
@pytest.fixture(scope="function")
def setup_teardown():
    with allure.step("初始化测试环境"):
        print("\n--- 测试开始 ---")
    yield
    with allure.step("清理测试环境"):
        print("\n--- 测试结束 ---")
