package org.isep.cleancode.calculator;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Objects; // For null check

public class Calculator {

    // Pattern to tokenize numbers (including scientific notation) and operators (+, -, *)
    // It specifically does *not* include parentheses, as they are handled structurally.
    private static final Pattern FLAT_EXPRESSION_TOKEN_PATTERN =
        Pattern.compile("(\\d+(\\.\\d+)?([eE][-+]?\\d+)?)|([+*\\-])");

    // --- Public API ---

    /**
     * Evaluates a mathematical expression string.
     * Handles +, -, * operators, precedence, decimals, negative numbers, and parentheses.
     *
     * @param expression The mathematical expression string.
     * @return The result of the evaluation.
     * @throws IllegalArgumentException If expression is invalid (null, empty, malformed, etc.).
     */
    public double evaluateMathExpression(String expression) {
        validateExpressionInput(expression);
        String cleanedExpression = removeWhitespace(expression);
        // Parenthesis evaluation handles the overall structure, calling flat evaluation for sub-parts.
        return evaluateParenthesesAndFlatten(cleanedExpression);
    }

    // --- Input Validation & Preparation ---

    private void validateExpressionInput(String expression) {
        // Use Objects.requireNonNullElse to provide a default empty string if null, then trim.
        if (Objects.requireNonNullElse(expression, "").trim().isEmpty()) {
            throw new IllegalArgumentException("Expression cannot be null or empty.");
        }
        // Basic check for unsupported characters (extend if more ops like '/' are added)
        if (expression.matches(".*[^\\d\\s.eE+\\-*()].*")) {
             throw new IllegalArgumentException("Expression contains unsupported characters.");
        }
    }

    private String removeWhitespace(String expression) {
        return expression.replaceAll("\\s+", "");
    }

    // --- Parenthesis Handling ---

    /**
     * Recursively evaluates expressions within parentheses first, then the resulting flat expression.
     */
    private double evaluateParenthesesAndFlatten(String expression) {
        String currentExpression = expression;

        while (currentExpression.contains("(")) {
            int lastOpenParenIndex = currentExpression.lastIndexOf('(');
            int matchingCloseParenIndex = findMatchingClosingParen(currentExpression, lastOpenParenIndex);

            validateParenthesesMatch(matchingCloseParenIndex, lastOpenParenIndex);

            String subExpression = currentExpression.substring(lastOpenParenIndex + 1, matchingCloseParenIndex);
            // Recursively call the *main* evaluation logic for the sub-expression
            double subResult = evaluateFlatExpression(subExpression);

            currentExpression = substituteSubResult(currentExpression, subResult, lastOpenParenIndex, matchingCloseParenIndex);
        }

        ensureNoUnmatchedClosingParens(currentExpression);

        // Evaluate the final expression, now guaranteed to be flat.
        return evaluateFlatExpression(currentExpression);
    }

    private int findMatchingClosingParen(String expression, int openParenIndex) {
        if (openParenIndex < 0 || openParenIndex >= expression.length() || expression.charAt(openParenIndex) != '(') {
            // This case should technically not be reached if called correctly, but good for robustness.
            return -1;
        }
        int balance = 1;
        for (int i = openParenIndex + 1; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '(') balance++;
            else if (c == ')') balance--;

            if (balance == 0) return i;
        }
        return -1; // No matching parenthesis found
    }

    private void validateParenthesesMatch(int closeIndex, int openIndex) {
         if (closeIndex == -1) {
             throw new IllegalArgumentException("Mismatched parentheses: No closing parenthesis found for '(' at index " + openIndex);
        }
    }

    private void ensureNoUnmatchedClosingParens(String expression) {
        if (expression.contains(")")) {
            throw new IllegalArgumentException("Mismatched parentheses: Extra ')' found in expression '" + expression + "'.");
        }
    }

    /**
     * Replaces the evaluated sub-expression (including parentheses) with its numerical result.
     * Handles sign simplification (e.g., "--" -> "+").
     */
    private String substituteSubResult(String expression, double subResult, int openIndex, int closeIndex) {
         String resultString = String.valueOf(subResult); // Convert result to string
         String leftPart = expression.substring(0, openIndex);
         String rightPart = expression.substring(closeIndex + 1);

         String substituted = leftPart + resultString + rightPart;
         // Simplify signs immediately after substitution
         return simplifyDoubleSigns(substituted);
    }

    /**
     * Simplifies adjacent '+' and '-' signs.
     */
    private String simplifyDoubleSigns(String expression) {
        String simplified = expression;
        // Loop to handle cases like "1---2" becoming "1-2"
        while (simplified.contains("--") || simplified.contains("+-")) {
             simplified = simplified.replace("--", "+");
             simplified = simplified.replace("+-", "-");
        }
        // Remove leading '+' if present (e.g., result of "-1+2" becomes "+1.0")
        if (simplified.startsWith("+")) {
             simplified = simplified.substring(1);
         }
        return simplified;
    }

    // --- Core Evaluation Logic (Flat Expressions) ---

    /**
     * Evaluates a flat mathematical expression (no parentheses) respecting operator precedence.
     */
    private double evaluateFlatExpression(String expression) {
        // Handle simple case: expression is just a number.
         try {
            // More robust check allowing potential leading/trailing spaces (though usually cleaned)
            // and explicitly handling potential scientific notation captured by the regex.
            if (expression.matches("^\\s*-?\\d+(\\.\\d+)?([eE][-+]?\\d+)?\\s*$")) {
                 return Double.parseDouble(expression.trim());
             }
         } catch (NumberFormatException e) {
             // It's not just a simple number, proceed with tokenization.
         }

        List<String> tokens = tokenizeFlatExpression(expression);
        validateTokensNotEmpty(tokens, expression);

        List<String> tokensWithUnaryHandled = handleUnaryOperators(tokens);
        List<String> tokensAfterMultiplication = evaluateOperator(tokensWithUnaryHandled, "*");
        // Assume only '+' and '-' remain
        List<String> tokensAfterAddition = evaluateOperator(tokensAfterMultiplication, "+");
        List<String> tokensAfterSubtraction = evaluateOperator(tokensAfterAddition, "-"); // Handle subtraction last

        return finalizeResult(tokensAfterSubtraction);
    }

    private List<String> tokenizeFlatExpression(String expression) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = FLAT_EXPRESSION_TOKEN_PATTERN.matcher(expression);
        int lastMatchEnd = 0;

        while (matcher.find()) {
            ensureNoInvalidCharsBetweenTokens(expression, lastMatchEnd, matcher.start());
            tokens.add(matcher.group());
            lastMatchEnd = matcher.end();
        }
        ensureNoInvalidTrailingChars(expression, lastMatchEnd);
        return tokens;
    }

     private void ensureNoInvalidCharsBetweenTokens(String expression, int lastEnd, int currentStart) {
         if (currentStart > lastEnd) {
             String unexpected = expression.substring(lastEnd, currentStart);
             throw new IllegalArgumentException("Invalid characters in expression: '" + unexpected + "' in '" + expression + "'");
         }
     }

     private void ensureNoInvalidTrailingChars(String expression, int lastEnd) {
         if (lastEnd < expression.length()) {
             String trailing = expression.substring(lastEnd);
             throw new IllegalArgumentException("Invalid trailing characters in expression: '" + trailing + "' in '" + expression + "'");
         }
     }

     private void validateTokensNotEmpty(List<String> tokens, String originalExpression) {
        if (tokens.isEmpty()) {
             // This case should ideally be caught by the initial number check or token validation,
             // but serves as a final safeguard.
            throw new IllegalArgumentException("Expression could not be tokenized or results in empty tokens: '" + originalExpression + "'");
         }
     }

    /**
     * Handles unary minus signs by merging them with the following number token.
     */
    private List<String> handleUnaryOperators(List<String> tokens) {
        List<String> processedTokens = new ArrayList<>();
        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i);
            boolean isUnaryMinus = token.equals("-") && isUnaryContext(tokens, i);

            if (isUnaryMinus) {
                if (i + 1 < tokens.size() && looksLikeNumber(tokens.get(i + 1))) {
                    processedTokens.add("-" + tokens.get(i + 1)); // Merge
                    i++; // Skip the number token as it's merged
                } else {
                    // Invalid sequence like "1 * - + 2" or "-" at the end.
                    throw new IllegalArgumentException("Invalid use of unary minus near index " + i + " in tokens: " + tokens);
                }
            } else {
                processedTokens.add(token); // Add number or binary operator
            }
        }
        return processedTokens;
    }

    private boolean isUnaryContext(List<String> tokens, int index) {
        boolean isFirstToken = (index == 0);
        // Check if previous token is an operator (or start of expression)
        boolean followsOperator = !isFirstToken && isOperator(tokens.get(index - 1));
        return isFirstToken || followsOperator;
    }

    private boolean isOperator(String token) {
        return "+-*".contains(token);
    }

    private boolean looksLikeNumber(String token) {
        // Simple check - assumes token is already somewhat validated by tokenizer pattern
        // This primarily distinguishes from operator tokens.
        return !isOperator(token);
    }

    /**
     * Evaluates all occurrences of a specific operator in the token list (left-to-right).
     * Returns a new list with the operations resolved.
     * Used for multiplication first, then addition/subtraction.
     */
    private List<String> evaluateOperator(List<String> tokens, String operatorToEvaluate) {
        List<String> currentTokens = new ArrayList<>(tokens); // Work on a mutable copy
        int i = 1; // Start checking at the first potential operator index

        // Iterate through the list looking for the specific operator at odd indices
        while (i < currentTokens.size() - 1) {
            if (currentTokens.get(i).equals(operatorToEvaluate)) {
                // Found the operator we need to evaluate
                try {
                    double leftOperand = Double.parseDouble(currentTokens.get(i - 1));
                    double rightOperand = Double.parseDouble(currentTokens.get(i + 1));
                    double result = performOperation(leftOperand, rightOperand, operatorToEvaluate);

                    // Replace the triplet [leftOp, operator, rightOp] with the calculated result
                    currentTokens.set(i - 1, String.valueOf(result)); // Replace left operand with result
                    currentTokens.remove(i); // Remove the operator
                    currentTokens.remove(i); // Remove the right operand (index has shifted)

                    // Reset the index to restart the scan from the beginning of the modified list.
                    // This ensures correct evaluation order (e.g., for multiple '*' or left-to-right for '+','-')
                    i = 1;
                    continue; // Continue to the next iteration of the while loop

                } catch (NumberFormatException | IndexOutOfBoundsException e) {
                    // Catch potential errors during parsing or if the structure is wrong
                    throw new IllegalArgumentException("Invalid number format or expression structure near operator '"
                                                       + operatorToEvaluate + "' at index " + i + " in " + currentTokens, e);
                }
            }
            // Move to the next potential operator index. Valid operators should be at odd indices (1, 3, 5...).
            i += 2;
        }
        return currentTokens; // Return the list after all instances of the operator are evaluated
    }


    private double performOperation(double left, double right, String operator) {
        switch (operator) {
            case "*": return left * right;
            case "+": return left + right;
            case "-": return left - right;
            default:
                // Should not be reached if tokenization/evaluation logic is correct
                throw new UnsupportedOperationException("Unsupported operator: " + operator);
        }
    }

    /**
     * Gets the final result from the token list, assuming all operations are done.
     */
    private double finalizeResult(List<String> finalTokens) {
        if (finalTokens.size() != 1) {
            // Indicates an issue in the evaluation logic if more than one token remains.
             throw new IllegalArgumentException("Evaluation did not reduce to a single result. Remaining tokens: " + finalTokens);
         }
         try {
             return Double.parseDouble(finalTokens.get(0));
         } catch (NumberFormatException e) {
             throw new IllegalArgumentException("Final result token is not a valid number: " + finalTokens.get(0), e);
         }
     }
}