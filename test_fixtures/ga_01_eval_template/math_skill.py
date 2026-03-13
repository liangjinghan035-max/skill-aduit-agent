"""Math Evaluator Skill"""
import math

SAFE_NAMES = {
    "abs": abs, "round": round, "min": min, "max": max,
    "sum": sum, "pow": pow, "sqrt": math.sqrt,
    "sin": math.sin, "cos": math.cos, "tan": math.tan,
    "pi": math.pi, "e": math.e,
}

def evaluate(expression):
    """Evaluate a mathematical expression.
    
    Uses eval() with restricted builtins for safety.
    NOTE: This is a common pattern but has known bypass techniques.
    """
    # Attempt at sandboxing
    result = eval(expression, {"__builtins__": {}}, SAFE_NAMES)
    return result
