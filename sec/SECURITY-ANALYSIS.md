# Security Analysis Guide for `cyrus-sasl-oauth2-oidc`

This guide explains how to use the **Docker-based security-analysis environment** to scan the C code of the `cyrus-sasl-oauth2-oidc` plugin.

## Included Analysis Tools

### 1. Main Static Analyzers
- **Cppcheck** – C/C++ static analyzer (errors, dead code, vulnerabilities)
- **Clang Static Analyzer** – In-depth symbolic analysis  
- **Splint** – Security-oriented analyzer with annotations

### 2. Vulnerability Detection
- **Flawfinder** – Fast vulnerability scanner
- **RATS** – Security vulnerability scanner
- **Dangerous-function search** – `strcpy`, `sprintf`, `malloc`, etc.

### 3. Code Quality
- **PMD CPD** – Duplicate-code detector
- **OCLint** – Quality & “code-smell” analyzer
- **Frama-C** – Formal-analysis platform (advanced)

### 4. Additional Tools
- **Valgrind** – Runtime memory-leak detection
- **TODO/FIXME search** – Comments to address

## Quick Usage

### Installation and First Run
```bash
# 1. Build the analysis Docker image
./security-analysis.sh build

# 2. Run the full analysis (recommended)
./security-analysis.sh analyze

# 3. View the results
./security-analysis.sh view
```

### Faster (Quick) Analysis
```bash
# Quick analysis (5–10 min vs 20–30 min)
./security-analysis.sh quick
```

### Interactive Shell for Manual Analysis
```bash
# Open a shell inside the container
./security-analysis.sh bash

# Inside the container you can use:
splint +bounds +null +charint src/*.c
cppcheck --enable=all src/
flawfinder src/
```

## Report Structure

After analysis, reports are generated in `./security-reports/`:

```
security-reports/
├── ANALYSIS_SUMMARY.md          # Overall summary
├── cppcheck-report.{txt,xml}    # Cppcheck analysis
├── clang-static-analyzer/       # Clang HTML reports
├── splint-report.txt            # Splint security analysis
├── flawfinder-report.{txt,html} # Flawfinder vulnerabilities
├── rats-report.{txt,html}       # RATS vulnerabilities
├── cpd-report.{txt,xml}         # PMD duplicate code
├── oclint-report.html           # OCLint quality
├── unsafe-functions.txt         # Potentially dangerous functions
└── todo-fixme.txt               # TODO/FIXME comments
```

## Result Interpretation

### Security Priorities

#### 🔴 Critical (fix immediately)
- Buffer overflows (Cppcheck, Splint)
- Null-pointer dereferences
- Use-after-free / double-free
- Format-string vulnerabilities

#### 🟠 Important (fix soon)
- Memory leaks
- Uninitialized variables
- Input-validation issues
- Unsafe functions (`strcpy`, `sprintf`)

#### 🟡 Moderate (fix in upcoming releases)
- High code duplication (> 100 tokens)
- Dead code (unused functions)
- Style issues

#### 🟢 Informational
- Minor code smells
- TODO/FIXME comments

### Tool-Specific Analysis

#### Cppcheck
```bash
# Show only critical errors
grep -E "(error|warning)" security-reports/cppcheck-report.txt

# Count problems by type
grep -o '\[[^]]*\]' security-reports/cppcheck-report.txt | sort | uniq -c
```

#### Splint (Security Focus)
```bash
cat security-reports/splint-report.txt
```

#### Flawfinder
```bash
# Show only level 4–5 vulnerabilities (critical)
grep -E "\\[4\\]|\\[5\\]" security-reports/flawfinder-report.txt
```

## Specialized OAuth2/OIDC Analysis

### Key Focus Areas

1. **JWT Token Handling**  
   – Signature validation  
   – Claim verification (`iss`, `aud`, `exp`)  
   – No logging of raw tokens

2. **Secret Memory Handling**  
   – Secure wiping of tokens/secrets  
   – No core dumps with sensitive data

3. **Input Validation**  
   – Secure JSON parsing  
   – Issuer-URL validation  
   – Buffer sizes for tokens

4. **Network Communication**  
   – SSL/TLS verification  
   – Proper time-outs  
   – HTTP error handling

### Specialized Analysis Commands

```bash
# Inside interactive shell (./security-analysis.sh bash)

# 1. Search for secret handling
grep -r -n "token\|secret\|password" src/

# 2. Check memory wiping
grep -r -n "memset\|bzero\|explicit_bzero" src/

# 3. Analyze JWT validation
grep -r -n -A5 -B5 "jwt\|verify\|signature" src/

# 4. Check HTTP error handling
grep -r -n -A3 "curl\|http\|ssl" src/

# 5. Analyze memory allocations
grep -r -n "malloc\|calloc\|realloc\|free" src/
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Analysis
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Analysis
        run: |
          ./security-analysis.sh build
          ./security-analysis.sh quick
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: security-reports/
```

### GitLab CI Example
```yaml
security_analysis:
  stage: test
  script:
    - ./security-analysis.sh build
    - ./security-analysis.sh analyze
  artifacts:
    paths:
      - security-reports/
    reports:
      junit: security-reports/*.xml
```

## Advanced Analysis with Frama-C

For deeper formal analysis:

```bash
# Inside interactive shell
./security-analysis.sh bash

# Abstract-value analysis
frama-c -val src/*.c

# Dead-code detection
frama-c -dead-code src/*.c

# ACSL analysis (if annotations exist)
frama-c -wp src/*.c
```

## Useful Commands

### Cleanup
```bash
# Remove all reports and the Docker image
./security-analysis.sh clean
```

### No-Cache Builds
```bash
# Force image rebuild
./security-analysis.sh build --no-cache
```

### Analyze Specific Files
```bash
# Inside interactive shell
./security-analysis.sh bash

# Analyze a specific file
cppcheck --enable=all src/oauth2_server.c
splint +bounds +null src/oauth2_server.c
flawfinder src/oauth2_server.c
```

## Customization

### Adjust Analysis Thresholds
Edit `Dockerfile.security-analysis` to tweak settings:
```dockerfile
# Example: change CPD threshold from 50 to 30 tokens
--minimum-tokens 30

# Example: set Flawfinder minimum level from 0 to 2
--minlevel=2
```

### Add Extra Tools
```dockerfile
# Add in the Dockerfile
RUN apt-get install -y your-security-tool

# Add in the analysis script
echo "Running your-security-tool..."
your-security-tool src/ > "$REPORTS_DIR/your-tool-report.txt"
```

## Support & Troubleshooting

### Common Issues

1. **Docker not available**
   ```bash
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   ```

2. **Insufficient permissions**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   # Re-login or:
   newgrp docker
   ```

3. **Insufficient disk space**
   ```bash
   # Clean Docker
   docker system prune -a
   ```

### Debug Logs
```bash
# Enable detailed logs
export DOCKER_BUILDKIT=0
./security-analysis.sh build

# View container logs
docker logs [container-id]
```

## References
- [Cppcheck Manual](https://cppcheck.sourceforge.io/manual.pdf)
- [Clang Static Analyzer](https://clang-analyzer.llvm.org/)
- [Splint Manual](https://splint.org/manual/)
- [PMD Documentation](https://pmd.github.io/)
- [Flawfinder](https://dwheeler.com/flawfinder/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## Contributing

To improve this analysis environment:
1. Fork the project  
2. Add your tools in `Dockerfile.security-analysis`  
3. Update the `analyze.sh` script  
4. Test with `./security-analysis.sh quick`  
5. Submit a pull request