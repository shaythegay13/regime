import subprocess, sys
result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_mongo_integration.py", "-v", "--tb=short"],
    capture_output=True, text=True,
    cwd=r"C:\Users\shayb\Downloads\regime\sentinel"
)
out = result.stdout + result.stderr
with open("intg_out.txt", "w", encoding="utf-8") as f:
    f.write(out)
print(out[-3000:])  # print last 3000 chars
sys.exit(result.returncode)
