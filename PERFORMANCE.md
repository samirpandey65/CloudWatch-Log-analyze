# Performance Configuration

## Parallel Workers Configuration

The log analyzer uses parallel processing to speed up analysis. You can configure the number of workers.

### Current Settings

- **Default Workers:** 20 (increased from 10)
- **Configurable via:** Environment variable `MAX_WORKERS`

### How to Change Workers

#### Option 1: Environment Variable (Recommended)

**Windows:**
```cmd
set MAX_WORKERS=50
python dashboard.py
```

**Linux/Mac:**
```bash
export MAX_WORKERS=50
python dashboard.py
```

#### Option 2: Modify Code Directly

Edit `dashboard.py` line ~50:
```python
max_workers = int(os.environ.get('MAX_WORKERS', 20))  # Change 20 to your desired number
```

### Recommended Settings

| Log Size | Workers | Speed |
|----------|---------|-------|
| Small (<1000 IPs) | 10-20 | Fast |
| Medium (1000-5000 IPs) | 20-50 | Faster |
| Large (5000+ IPs) | 50-100 | Fastest |

### Performance Tips

1. **More Workers = Faster Processing**
   - Each worker processes geo-location lookups in parallel
   - More workers = more concurrent API calls

2. **API Rate Limits**
   - ipapi.co: 1000 requests/day (free)
   - ip-api.com: 45 requests/minute (free)
   - Consider upgrading for high volume

3. **System Resources**
   - More workers = more memory usage
   - Recommended: 2-4 workers per CPU core
   - Monitor system performance

4. **Optimal Settings**
   - **4 CPU cores:** 20-30 workers
   - **8 CPU cores:** 40-60 workers
   - **16+ CPU cores:** 80-100 workers

### Files Using Parallel Processing

1. **`analyze_attacks.py`**
   - Geo-location lookups (configurable)
   - Log parsing (single-threaded)

2. **`dashboard.py`**
   - Calls analyze_attacks with worker config
   - Default: 20 workers

3. **`fetch_and_analyze.py`**
   - CloudWatch log fetching (boto3 handles internally)

4. **`fetch_s3_logs.py`**
   - S3 log downloading (boto3 handles internally)

### Example Usage

**Fast Processing (50 workers):**
```cmd
set MAX_WORKERS=50
python dashboard.py
```

**Maximum Speed (100 workers):**
```cmd
set MAX_WORKERS=100
python dashboard.py
```

**Conservative (10 workers):**
```cmd
set MAX_WORKERS=10
python dashboard.py
```

### Monitoring Performance

Watch the console output:
```
Fetching geo data for 500 IPs using 50 workers...
```

This shows how many workers are being used.

### Troubleshooting

**Too Slow?**
- Increase MAX_WORKERS
- Check internet connection
- Verify API rate limits

**System Overload?**
- Decrease MAX_WORKERS
- Close other applications
- Check CPU/memory usage

**API Errors?**
- Reduce MAX_WORKERS (rate limiting)
- Wait and retry
- Consider paid API plans

### Advanced Configuration

For even more control, edit `analyze_attacks.py`:

```python
# Line 67 - Adjust sleep time between requests
time.sleep(0.1)  # Reduce to 0.05 for faster (but more aggressive)

# Line 67 - Change max_workers default
def get_geo_batch(ips, priority_ips=None, max_workers=20):  # Change default here
```

### Benchmark Results

| Workers | 1000 IPs | 5000 IPs | 10000 IPs |
|---------|----------|----------|-----------|
| 10 | ~2 min | ~10 min | ~20 min |
| 20 | ~1 min | ~5 min | ~10 min |
| 50 | ~30 sec | ~2 min | ~4 min |
| 100 | ~20 sec | ~1 min | ~2 min |

*Results vary based on network speed and API response times*
