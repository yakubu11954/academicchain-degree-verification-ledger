# AcademicChain Degree Verification Ledger

## Description
A tamper-evident degree and certificate verification system built on Stacks blockchain. This platform stores canonical hashes and maintains revocation lists, enabling global verification of academic credentials without exposing private data.

## Features
- Secure degree and certificate verification
- Tamper-evident blockchain storage
- Privacy-preserving verification (no exposure of private data)
- Global verification capabilities
- Revocation list management

## Prerequisites
- Node.js (v14 or higher)
- npm (Node Package Manager)
- Clarinet CLI for Stacks development

## Installation
1. Clone the repository
```bash
git clone <repository-url>
cd academicchain-degree-verification-ledger
```

2. Install dependencies
```bash
npm install
```

## Project Structure
```
academicchain-degree-verification-ledger/
├── contracts/          # Smart contracts (Clarity)
├── tests/              # Test files
├── settings/           # Configuration files
├── package.json        # Node.js dependencies
├── Clarinet.toml       # Clarinet configuration
├── tsconfig.json       # TypeScript configuration
└── vitest.config.js    # Test configuration
```

## Running Tests
Run unit tests:
```bash
npm test
```

Run tests with coverage report:
```bash
npm run test:report
```

Watch mode for development:
```bash
npm run test:watch
```

## Technologies Used
- **Stacks Blockchain**: For secure, decentralized storage
- **Clarity**: Smart contract language
- **Clarinet SDK**: Development framework
- **Vitest**: Testing framework
- **TypeScript**: Type-safe development

## License
ISC

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
