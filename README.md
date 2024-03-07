# FastAPI JWT Authentication

## Overview

This project showcases a secure authentication implementation using FastAPI, OAuth2, and JWT (JSON Web Tokens). The tutorial covers token generation, user validation, and integration with OAuth2 for password bearer authentication.

## Features

- **Token Generation:** Create secure access tokens for user authentication.
- **User Validation:** Implement methods to validate user credentials for secure access.
- **OAuth2 Integration:** Utilize OAuth2 for password bearer authentication in FastAPI.
- **JWT Encoding:** Explore JWT for encoding and decoding tokens with a custom secret key and algorithm.
- **Password Hashing:** Enhance security with bcrypt password hashing.
- **Dependency Injection:** Seamless integration of authentication checks using FastAPI's dependency injection.

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Epic-R-R/fastapi-jwt-authentication.git
   cd fastapi-jwt-authentication
   ```
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
1. Run the FastAPI application:

   ```bash
   hypercorn main:app --worker-class trio
   ```

Access the API documentation at ```http://127.0.0.1:8000/docs``` and explore the implemented endpoints.
