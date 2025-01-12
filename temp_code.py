import pickle
import subprocess

# Vulnerability 1: Hardcoded sensitive information (hardcoded password)
def authenticate(user, password):
    if password == "super_secret_password":  # Hardcoded password vulnerability
        return True
    else:
        return False

# Vulnerability 2: Use of eval() (Remote code execution vulnerability)
def evaluate_expression(expression):
    return eval(expression)  # Dangerous use of eval() can execute arbitrary code

# Vulnerability 3: Insecure deserialization
def load_data(serialized_data):
    return pickle.loads(serialized_data)  # Insecure deserialization vulnerability

# Vulnerability 4: Subprocess call with unsanitized input
def run_command(user_input):
    subprocess.call(user_input, shell=True)  # Command injection vulnerability

if __name__ == "__main__":
    # Test code
    user = input("Enter username: ")
    password = input("Enter password: ")
    
    if authenticate(user, password):
        print("Authenticated!")
    else:
        print("Authentication failed.")

    # Test eval
    expression = input("Enter a mathematical expression to evaluate: ")
    print(f"Result: {evaluate_expression(expression)}")

    # Test insecure deserialization
    serialized_data = input("Enter serialized data: ")
    load_data(serialized_data)

    # Test command injection
    command = input("Enter a command to run: ")
    run_command(command)
