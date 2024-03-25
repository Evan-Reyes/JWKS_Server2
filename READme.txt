# Project 2: Extending JWKS Server 2

## Description
This project is a Flask-based web application that provides functionalities for generating JSON Web Key Set (JWKS) and authenticating users using JSON Web Tokens (JWTs). It includes features such as key generation, database operations, and route handlers for serving JWKS and authenticating users.

## Features
- Generates RSA keys for signing JWTs
- Stores keys and their expiration dates in a SQLite database
- Provides a JWKS endpoint (`/.well-known/jwks.json`) for serving JSON Web Key Sets
- Supports user authentication via JWTs with configurable expiration times
- Implements security best practices for key management and token authentication
