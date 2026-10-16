# J26-CS-336 — Network Flow APT Detection

## Research Overview

Lightweight Ensemble-Based Multi-Signal APT Behavior Detection for IIoT Edge Gateways.

This branch contains the Network Flow Classification component of our final-year research.

## Current Implementation

- CICAPT-IIoT dataset auditing and feature quality analysis
- ToN-IoT network flow dataset analysis
- Network observation window processing: 5s, 10s, 15s, 20s
- Batch and streaming feature extraction
- ToN-IoT group-disjoint dataset splitting
- Machine learning preprocessing
- Automated unit testing

## Project Structure

- scripts/ — Dataset auditing and ML preparation scripts
- src/ — Network feature extraction code
- tests/ — Automated tests

## Setup

Python 3.12

Install dependencies:

pip install -r requirements.txt

## Research Status

The network-flow ML baseline is under development.
The four monitoring-window implementations have passed synthetic tests.
Real packet-level window labeling and validation remain future work.

Raw datasets and generated model files are excluded from GitHub.

SLIIT Final-Year Research — J26-CS-336
