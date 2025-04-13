package org.isep.cleancode.calculator;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class CalculatorTest {

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'6', 6",
            "'0', 0",
            "'548511', 548511"
    })
    void basicPositiveInteger(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'8.9', 8.9",
            "'1.0', 1",
            "'3.14', 3.14"
    })
    void basicFloatingPointNumber(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'1 + 1', 2",
            "'12 + 12', 24",
            "'13+12', 25",
            "'2+ 3', 5",
            "'8 +3', 11"
    })
    void basicAddition(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'1 + 1 + 1', 3",
            "'12 + 12 + 1', 25",
            "'13+12+11', 36",
            "'2+ 3+ 5', 10",
            "'8 +3+3', 14"
    })
    void multipleAdditions(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'1 - 1', 0",
            "'8-5', 3",
            "'13-14', -1",
            "'20-10-5', 5",
            "'5 - 0 - 4 - 0 - 3', -2"
    })
    void subtractions(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'0 * 0', 0",
            "'0 * 1', 0",
            "'1 * 0', 0",
            "'2 * 2', 4",
            "'1*2*3*4', 24",
            "'9 * 0.5', 4.5"
    })
    void multiplications(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
    @CsvSource({
            "'0 * 0 + 1', 1",
            "'1 + 2 * 2 + 1', 6",
            "'5 - 5 * 0 - 4', 1",
            "'10 - 2 * 10', -10"
    })
    void multipleOperations(String expression, double expectedValue) {
        Calculator calculator = new Calculator();

        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
    }

//    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
//    @CsvSource({
//            "'-15', -15",
//            "'-1', -1"
//    })
//    void basicNegativeInteger(String expression, double expectedValue) {
//        Calculator calculator = new Calculator();
//
//        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
//    }

//    @ParameterizedTest(name = "{index} => input={0}, expected={1}")
//    @CsvSource({
//            "'0 * (0 + 1)', 0",
//            "'(1 + 2) * 2 + 1', 7",
//            "'(1 + 2) * (2 + 1)', 9",
//            "'(5 - 5) * 0 - 4', -4",
//            "'(10 - 2) * 10', 80"
//    })
//    void multipleOperationsWithParenthesis(String expression, double expectedValue) {
//        Calculator calculator = new Calculator();
//
//        assertEquals(expectedValue, calculator.evaluateMathExpression(expression));
//    }
}