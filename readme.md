# Exercice :  🧮 **Build a Simple Calculator**

### **Objective:**
Your task is to implement a `Calculator` class in Java that evaluates basic mathematical expressions represented as strings. The goal is to make the provided set of unit tests pass.

---

### ✅ **What You'll Do**
You will implement the `evaluateMathExpression` method in a class named `Calculator`:

```java
public class Calculator {
    public double evaluateMathExpression(String expression) {
        // Your code here
    }
}
```

This method takes a mathematical expression in `String` form and returns the result as a `double`.

---

### 🧪 **Testing**
The test suite (`CalculatorTest`) covers multiple scenarios. Your implementation must make each test pass. These include:

- Evaluating **positive integers** and **floating-point numbers**
- Handling **addition**, **subtraction**, and **multiplication**
- Supporting **multiple operations** and respecting **operation precedence**

---

### 💡 **Guidelines**
- Your **code should be readable and not unnecessarily complex**.
- You are **encouraged to proceed incrementally**, making tests pass one at a time—just as you would in **Test-Driven Development (TDD)**.
- You are free to split your code into as many classes and methods as you want.
- Do **not** use any external libraries for expression parsing (like exp4j, JEval, etc.).
- Use only core Java functionality (e.g., `String`, `Math`, etc.).

---

### ⭐ **Bonus Challenges**
Two additional test cases are commented out:
- Support for **negative numbers**
- Support for **parentheses**

Uncomment these tests once you feel confident and want an extra challenge. Bonus points will be given for making them pass!

---

### 📝 **Submission**
- Lab to be completed **individually or in pairs**
- To be submitted **by email before May 6th 11:59**.
  - The subject of your mail should look like `Isep - CleanCode - TP1 - <firstName1> <lastName1> and <firstName2> <lastName2>`
  - In your mail, please **include short notes** (150 words max) explaining your methodology for developing the calculator as well as the difficulties you encountered (if any) and the assumptions you made.
- 0.5 **bonus points** will be awarded to students returning their assignment as a link to a **public git repository**. Students who submit the lab as a Git repo also have until May 6th 11:59 to add commits to their project, even if they sent the repo link to the teacher before this date.
- Questions about this lab can be submitted by email until April 23rd at 11:59 PM.
- Students are allowed to make this lab in another language than java as long as :
  - they port the unit tests
  - they include, as part of their submission, a very short note explaining the required tool to run the test, and how to run them.
  - the chosen language is one of : C#, F#, Scala, Clojure, Kotlin, JavaScript, Typescript, Python, PHP, C++, Go, Rust, Ruby, Swift
---

### 💯 **Rating system**
- **10 points for the overall quality of your code**: is your code understandable, or is it unnecessarily complex and opaque ? Does it respect most of SOLID principles as well as the design guidelines learnt in class ? Here are some reminders that may help you write clean code in this specific exercise :
  - **Single Responsibility Principle** : a class or a function should focus on one and only one thing. They should have no more than one reason to change
  - **Clear naming** : try to give meaningful names to classes, methods and variables.
  - **Avoid comments**. Explain yourself through the code.
  - **Keep things short**. If you find yourself writing a 200 lines long method, it means you can probably refactor it into multiple methods.
  - **Keep the level of nesting as low as possible**. You don't want an if inside an if inside an if.
- **10 points for making your code work**, i.e making tests pass.
- **1 bonus point** for having the negative number test pass (if all non bonus tests also pass)
- **1.5 bonus point** for having the parenthesis test pass (if all non bonus tests also pass)
- **0.5 bonus points** for returning the assignment as a public git repository
---

### 🧠 **Hint**
Start simple! Try to make tests pass one at a time and to refactor your code when it gets too complex.

Good luck, and remember to focus on code readibility ! 🧠💻

--- 