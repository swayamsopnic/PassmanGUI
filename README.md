# Password Management Application

## Overview

This is a password management application developed using Python's Tkinter library. It provides functionalities for managing passwords, usernames, and user information. The application includes features for changing usernames and passwords, updating login details, generating secure passwords, and checking password strength.

## Features

- **Change Username**: Update the username for a given ID.
- **Change Password**: Update the password for a given ID.
- **Update Login Username/Password**: Update the login username or password.
- **Password Generator**: Generate random passwords with specified criteria.
- **Password Strength Meter**: Check the strength of a given password.
- **Security Reports**: Generate domain, email breach, password breach, and username breach reports.

## Installation

1. Clone this repository to your local machine:
    ```bash
    git clone https://github.com/yourusername/your-repository.git
    ```

2. Navigate to the project directory:
    ```bash
    cd your-repository
    ```

3. Install the required packages (if any):
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the main application script:
    ```bash
    python main.py
    ```

2. The application window will open, providing a menu for various functionalities.

## Code Structure

- **`main.py`**: The main script containing the application logic and Tkinter UI setup.
- **`utils.py`**: (Optional) Utility functions for encryption, decryption, and password generation (if separated).
- **`requirements.txt`**: Lists the dependencies required for the application.

## Example Functions

### Generate Password

```python
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True):
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
### Check Password Strength

```python
def password_strength(password):
    length_criteria = len(password) >= 12
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    symbol_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, symbol_criteria])

    if score == 5:
        return 'Strong'
    elif score >= 3:
        return 'Medium'
    else:
        return 'Weak'
## Contributing

Feel free to fork the repository and submit pull requests for improvements or bug fixes. Please follow the code style guidelines and include tests for new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries, please contact [your.email@example.com](mailto:your.email@example.com).
