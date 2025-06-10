# Secure Robotic Arm Control System

## Overview

The **Secure Robotic Arm Control System** is a Python application that simulates a robotic arm controlled securely through a graphical interface. The system leverages object-oriented programming (OOP) principles and emphasizes security and modularity. It uses RSA encryption to securely transmit commands and SHA-256 hashing for user authentication.

---

## Features

- **User Authentication:** Secure registration and login with password hashing (SHA-256).
- **Robotic Arm Control:** Define the number and lengths of arm segments and control each segment's angle.
- **Real-Time Visualization:** Visual feedback of the robotic arm's movement.
- **Secure Communication:** Commands are encrypted using RSA to ensure secure transmission.
- **Modular Design:** Clear separation of concerns with dedicated classes for users, commands, and secure communication.


## Requirements

- Python 3.6 or higher
- `cryptography` library

Install the required library via pip:

```bash
pip install cryptography


## GUI Usage

| Field               | Description                                      | Example        |
|---------------------|--------------------------------------------------|----------------|
| Number of Segments  | Total number of segments in the robotic arm      | 3              |
| Segment Lengths     | Comma-separated lengths of each segment         | 100,80,60      |
| Segment Index       | Index of the segment to rotate (0-based)        | 0 (first segment) |
| Angle (degrees)     | Rotation angle for the selected segment         | 45 (degrees)   |
