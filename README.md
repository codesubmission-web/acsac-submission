# SPARC: Server-aided PUF-based Authentication Resilient to Server Compromise

This repository contains the implementation of the proposed protocol in the paper.

---

# Repository Structure

```text
env.yml
symmetric[32/64/128]
├── extprotocol-client-serv32.py
├── challenge_server32.py
├── challenge_client32.py
├── challenge_puf32.py
```

---

# Dependencies

We provide a Conda environment file (`env.yml`) containing all required dependencies.

Users can either:

- directly create the Conda environment using the provided YAML file, or
- manually inspect the dependencies from the YAML/requirements files.

---

# Environment Setup

## Clone the repository

```bash
git clone <repository_link>
cd <repository_name>
```

---

## Create Conda Environment

```bash
conda env create -f env.yml
```

---

## Activate Environment

```bash
conda activate <environment_name>
```

---

## Alternative Installation

If Conda installation does not work on your system:

```bash
pip install -r requirements.txt
```

---

# Execution Workflow

The protocol execution consists of four major stages:

1. Key and model generation
2. Extended protocol initialization
3. Server execution
4. PUF and client execution

---

# Step 1: Generate Keys and Required Models

Run the extended protocol initialization script:

```bash
python extprotocol-client-serv32.py
```

This step generates:

- cryptographic keys,
- required models,
- protocol initialization parameters,
- and all required setup files.

Ensure this step completes successfully before proceeding further.

---

# Step 2: Run the Server

Start the server process:

```bash
python challenge_server32.py
```

The server should remain active and listening for incoming connections.

---

# Step 3: Run the PUF Module

In a separate terminal:

```bash
python challenge_puf32.py
```

This initializes the PUF challenge-response functionality.

---

# Step 4: Run the Client

Finally, execute the client:

```bash
python challenge_client32.py
```

The client communicates with the server and PUF modules to execute the complete protocol.

---

# License

This project is intended for academic and research purposes.
